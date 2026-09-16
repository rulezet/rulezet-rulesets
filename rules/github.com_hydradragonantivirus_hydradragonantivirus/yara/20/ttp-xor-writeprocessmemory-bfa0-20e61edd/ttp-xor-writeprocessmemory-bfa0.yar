rule TTP_XOR_WriteProcessMemory_bfa0 {
  strings:
    $key_bfa0 = { e8 d2 [2] da f0 [2] dc c5 [2] f2 c5 [2] cd d9 }

  condition:
    any of them
}