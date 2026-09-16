rule TTP_XOR_WriteProcessMemory_b962 {
  strings:
    $key_b962 = { ee 10 [2] dc 32 [2] da 07 [2] f4 07 [2] cb 1b }

  condition:
    any of them
}