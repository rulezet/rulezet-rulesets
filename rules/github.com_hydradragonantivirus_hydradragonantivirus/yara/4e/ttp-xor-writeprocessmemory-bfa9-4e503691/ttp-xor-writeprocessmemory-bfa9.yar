rule TTP_XOR_WriteProcessMemory_bfa9 {
  strings:
    $key_bfa9 = { e8 db [2] da f9 [2] dc cc [2] f2 cc [2] cd d0 }

  condition:
    any of them
}