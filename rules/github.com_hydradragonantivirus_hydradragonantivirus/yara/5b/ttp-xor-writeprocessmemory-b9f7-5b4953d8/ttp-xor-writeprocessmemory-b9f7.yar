rule TTP_XOR_WriteProcessMemory_b9f7 {
  strings:
    $key_b9f7 = { ee 85 [2] dc a7 [2] da 92 [2] f4 92 [2] cb 8e }

  condition:
    any of them
}