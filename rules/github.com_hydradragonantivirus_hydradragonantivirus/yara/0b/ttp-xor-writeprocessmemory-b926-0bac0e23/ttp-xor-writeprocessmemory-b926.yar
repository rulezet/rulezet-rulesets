rule TTP_XOR_WriteProcessMemory_b926 {
  strings:
    $key_b926 = { ee 54 [2] dc 76 [2] da 43 [2] f4 43 [2] cb 5f }

  condition:
    any of them
}