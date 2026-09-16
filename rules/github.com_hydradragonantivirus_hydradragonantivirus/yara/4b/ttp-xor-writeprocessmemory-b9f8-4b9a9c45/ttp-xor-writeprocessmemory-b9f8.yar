rule TTP_XOR_WriteProcessMemory_b9f8 {
  strings:
    $key_b9f8 = { ee 8a [2] dc a8 [2] da 9d [2] f4 9d [2] cb 81 }

  condition:
    any of them
}