rule TTP_XOR_WriteProcessMemory_bfb4 {
  strings:
    $key_bfb4 = { e8 c6 [2] da e4 [2] dc d1 [2] f2 d1 [2] cd cd }

  condition:
    any of them
}