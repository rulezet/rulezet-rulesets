rule TTP_XOR_WriteProcessMemory_b9f5 {
  strings:
    $key_b9f5 = { ee 87 [2] dc a5 [2] da 90 [2] f4 90 [2] cb 8c }

  condition:
    any of them
}