rule TTP_XOR_WriteProcessMemory_bfa4 {
  strings:
    $key_bfa4 = { e8 d6 [2] da f4 [2] dc c1 [2] f2 c1 [2] cd dd }

  condition:
    any of them
}