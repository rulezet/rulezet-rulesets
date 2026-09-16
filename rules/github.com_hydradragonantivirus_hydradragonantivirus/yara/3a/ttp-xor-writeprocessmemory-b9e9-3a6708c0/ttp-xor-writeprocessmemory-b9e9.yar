rule TTP_XOR_WriteProcessMemory_b9e9 {
  strings:
    $key_b9e9 = { ee 9b [2] dc b9 [2] da 8c [2] f4 8c [2] cb 90 }

  condition:
    any of them
}