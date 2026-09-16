rule TTP_XOR_WriteProcessMemory_bfd6 {
  strings:
    $key_bfd6 = { e8 a4 [2] da 86 [2] dc b3 [2] f2 b3 [2] cd af }

  condition:
    any of them
}