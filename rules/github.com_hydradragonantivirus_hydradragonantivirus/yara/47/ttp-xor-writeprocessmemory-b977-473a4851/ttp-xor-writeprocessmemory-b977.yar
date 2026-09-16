rule TTP_XOR_WriteProcessMemory_b977 {
  strings:
    $key_b977 = { ee 05 [2] dc 27 [2] da 12 [2] f4 12 [2] cb 0e }

  condition:
    any of them
}