rule TTP_XOR_WriteProcessMemory_b9fc {
  strings:
    $key_b9fc = { ee 8e [2] dc ac [2] da 99 [2] f4 99 [2] cb 85 }

  condition:
    any of them
}