rule TTP_XOR_WriteProcessMemory_bfd7 {
  strings:
    $key_bfd7 = { e8 a5 [2] da 87 [2] dc b2 [2] f2 b2 [2] cd ae }

  condition:
    any of them
}