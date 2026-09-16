rule TTP_XOR_WriteProcessMemory_b912 {
  strings:
    $key_b912 = { ee 60 [2] dc 42 [2] da 77 [2] f4 77 [2] cb 6b }

  condition:
    any of them
}