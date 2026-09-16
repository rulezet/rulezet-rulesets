rule TTP_XOR_WriteProcessMemory_b90b {
  strings:
    $key_b90b = { ee 79 [2] dc 5b [2] da 6e [2] f4 6e [2] cb 72 }

  condition:
    any of them
}