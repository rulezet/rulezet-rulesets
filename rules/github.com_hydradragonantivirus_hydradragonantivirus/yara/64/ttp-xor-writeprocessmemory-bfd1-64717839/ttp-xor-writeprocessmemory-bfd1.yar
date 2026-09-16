rule TTP_XOR_WriteProcessMemory_bfd1 {
  strings:
    $key_bfd1 = { e8 a3 [2] da 81 [2] dc b4 [2] f2 b4 [2] cd a8 }

  condition:
    any of them
}