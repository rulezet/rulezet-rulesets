rule TTP_XOR_WriteProcessMemory_b97e {
  strings:
    $key_b97e = { ee 0c [2] dc 2e [2] da 1b [2] f4 1b [2] cb 07 }

  condition:
    any of them
}