rule TTP_XOR_WriteProcessMemory_bfb0 {
  strings:
    $key_bfb0 = { e8 c2 [2] da e0 [2] dc d5 [2] f2 d5 [2] cd c9 }

  condition:
    any of them
}