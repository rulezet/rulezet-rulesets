rule TTP_XOR_WriteProcessMemory_b9f9 {
  strings:
    $key_b9f9 = { ee 8b [2] dc a9 [2] da 9c [2] f4 9c [2] cb 80 }

  condition:
    any of them
}