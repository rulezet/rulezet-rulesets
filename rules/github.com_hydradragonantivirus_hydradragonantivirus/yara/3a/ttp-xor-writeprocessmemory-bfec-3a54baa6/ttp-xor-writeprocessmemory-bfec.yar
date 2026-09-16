rule TTP_XOR_WriteProcessMemory_bfec {
  strings:
    $key_bfec = { e8 9e [2] da bc [2] dc 89 [2] f2 89 [2] cd 95 }

  condition:
    any of them
}