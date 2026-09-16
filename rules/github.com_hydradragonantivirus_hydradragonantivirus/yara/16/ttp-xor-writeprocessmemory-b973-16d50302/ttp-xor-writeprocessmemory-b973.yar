rule TTP_XOR_WriteProcessMemory_b973 {
  strings:
    $key_b973 = { ee 01 [2] dc 23 [2] da 16 [2] f4 16 [2] cb 0a }

  condition:
    any of them
}