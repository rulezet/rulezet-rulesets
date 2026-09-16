rule TTP_XOR_WriteProcessMemory_b9eb {
  strings:
    $key_b9eb = { ee 99 [2] dc bb [2] da 8e [2] f4 8e [2] cb 92 }

  condition:
    any of them
}