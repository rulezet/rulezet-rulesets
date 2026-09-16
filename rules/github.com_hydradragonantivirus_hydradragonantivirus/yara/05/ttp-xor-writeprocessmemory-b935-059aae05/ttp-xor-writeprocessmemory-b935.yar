rule TTP_XOR_WriteProcessMemory_b935 {
  strings:
    $key_b935 = { ee 47 [2] dc 65 [2] da 50 [2] f4 50 [2] cb 4c }

  condition:
    any of them
}