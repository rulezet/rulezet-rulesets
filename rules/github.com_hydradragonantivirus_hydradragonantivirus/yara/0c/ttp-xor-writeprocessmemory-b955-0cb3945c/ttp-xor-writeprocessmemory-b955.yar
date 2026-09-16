rule TTP_XOR_WriteProcessMemory_b955 {
  strings:
    $key_b955 = { ee 27 [2] dc 05 [2] da 30 [2] f4 30 [2] cb 2c }

  condition:
    any of them
}