rule TTP_XOR_WriteProcessMemory_bfa5 {
  strings:
    $key_bfa5 = { e8 d7 [2] da f5 [2] dc c0 [2] f2 c0 [2] cd dc }

  condition:
    any of them
}