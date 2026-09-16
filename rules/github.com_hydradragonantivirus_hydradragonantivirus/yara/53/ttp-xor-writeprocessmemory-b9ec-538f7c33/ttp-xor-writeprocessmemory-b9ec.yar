rule TTP_XOR_WriteProcessMemory_b9ec {
  strings:
    $key_b9ec = { ee 9e [2] dc bc [2] da 89 [2] f4 89 [2] cb 95 }

  condition:
    any of them
}