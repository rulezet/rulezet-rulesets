rule TTP_XOR_WriteProcessMemory_b9f2 {
  strings:
    $key_b9f2 = { ee 80 [2] dc a2 [2] da 97 [2] f4 97 [2] cb 8b }

  condition:
    any of them
}