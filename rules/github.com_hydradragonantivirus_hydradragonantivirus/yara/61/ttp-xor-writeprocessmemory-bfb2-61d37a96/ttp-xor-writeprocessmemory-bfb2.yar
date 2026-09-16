rule TTP_XOR_WriteProcessMemory_bfb2 {
  strings:
    $key_bfb2 = { e8 c0 [2] da e2 [2] dc d7 [2] f2 d7 [2] cd cb }

  condition:
    any of them
}