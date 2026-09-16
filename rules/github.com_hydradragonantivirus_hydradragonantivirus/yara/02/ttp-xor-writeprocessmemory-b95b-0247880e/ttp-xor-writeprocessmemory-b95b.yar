rule TTP_XOR_WriteProcessMemory_b95b {
  strings:
    $key_b95b = { ee 29 [2] dc 0b [2] da 3e [2] f4 3e [2] cb 22 }

  condition:
    any of them
}