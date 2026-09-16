rule TTP_XOR_WriteProcessMemory_b956 {
  strings:
    $key_b956 = { ee 24 [2] dc 06 [2] da 33 [2] f4 33 [2] cb 2f }

  condition:
    any of them
}