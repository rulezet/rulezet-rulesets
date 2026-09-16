rule TTP_XOR_WriteProcessMemory_b97b {
  strings:
    $key_b97b = { ee 09 [2] dc 2b [2] da 1e [2] f4 1e [2] cb 02 }

  condition:
    any of them
}