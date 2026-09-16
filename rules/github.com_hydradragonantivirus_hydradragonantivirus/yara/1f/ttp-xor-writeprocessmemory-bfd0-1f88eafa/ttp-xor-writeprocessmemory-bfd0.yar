rule TTP_XOR_WriteProcessMemory_bfd0 {
  strings:
    $key_bfd0 = { e8 a2 [2] da 80 [2] dc b5 [2] f2 b5 [2] cd a9 }

  condition:
    any of them
}