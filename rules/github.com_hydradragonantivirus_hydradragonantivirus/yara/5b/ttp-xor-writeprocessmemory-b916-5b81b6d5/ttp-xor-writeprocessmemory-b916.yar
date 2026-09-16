rule TTP_XOR_WriteProcessMemory_b916 {
  strings:
    $key_b916 = { ee 64 [2] dc 46 [2] da 73 [2] f4 73 [2] cb 6f }

  condition:
    any of them
}