rule TTP_XOR_WriteProcessMemory_b936 {
  strings:
    $key_b936 = { ee 44 [2] dc 66 [2] da 53 [2] f4 53 [2] cb 4f }

  condition:
    any of them
}