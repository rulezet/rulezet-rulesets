rule TTP_XOR_WriteProcessMemory_b9f3 {
  strings:
    $key_b9f3 = { ee 81 [2] dc a3 [2] da 96 [2] f4 96 [2] cb 8a }

  condition:
    any of them
}