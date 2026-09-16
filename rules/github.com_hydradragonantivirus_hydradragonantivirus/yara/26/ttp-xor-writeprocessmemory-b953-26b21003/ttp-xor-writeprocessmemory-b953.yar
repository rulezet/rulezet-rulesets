rule TTP_XOR_WriteProcessMemory_b953 {
  strings:
    $key_b953 = { ee 21 [2] dc 03 [2] da 36 [2] f4 36 [2] cb 2a }

  condition:
    any of them
}