rule TTP_XOR_WriteProcessMemory_bfc5 {
  strings:
    $key_bfc5 = { e8 b7 [2] da 95 [2] dc a0 [2] f2 a0 [2] cd bc }

  condition:
    any of them
}