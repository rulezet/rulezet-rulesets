rule TTP_XOR_WriteProcessMemory_b96b {
  strings:
    $key_b96b = { ee 19 [2] dc 3b [2] da 0e [2] f4 0e [2] cb 12 }

  condition:
    any of them
}