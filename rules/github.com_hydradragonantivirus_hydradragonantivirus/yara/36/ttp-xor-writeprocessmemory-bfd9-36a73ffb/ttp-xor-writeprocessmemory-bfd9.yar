rule TTP_XOR_WriteProcessMemory_bfd9 {
  strings:
    $key_bfd9 = { e8 ab [2] da 89 [2] dc bc [2] f2 bc [2] cd a0 }

  condition:
    any of them
}