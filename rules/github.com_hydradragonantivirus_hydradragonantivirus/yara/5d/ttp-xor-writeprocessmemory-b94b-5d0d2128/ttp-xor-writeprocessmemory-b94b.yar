rule TTP_XOR_WriteProcessMemory_b94b {
  strings:
    $key_b94b = { ee 39 [2] dc 1b [2] da 2e [2] f4 2e [2] cb 32 }

  condition:
    any of them
}