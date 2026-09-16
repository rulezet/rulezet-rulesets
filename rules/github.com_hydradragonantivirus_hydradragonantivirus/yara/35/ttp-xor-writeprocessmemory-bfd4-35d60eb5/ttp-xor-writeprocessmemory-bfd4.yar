rule TTP_XOR_WriteProcessMemory_bfd4 {
  strings:
    $key_bfd4 = { e8 a6 [2] da 84 [2] dc b1 [2] f2 b1 [2] cd ad }

  condition:
    any of them
}