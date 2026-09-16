rule TTP_XOR_WriteProcessMemory_bf7b {
  strings:
    $key_bf7b = { e8 09 [2] da 2b [2] dc 1e [2] f2 1e [2] cd 02 }

  condition:
    any of them
}