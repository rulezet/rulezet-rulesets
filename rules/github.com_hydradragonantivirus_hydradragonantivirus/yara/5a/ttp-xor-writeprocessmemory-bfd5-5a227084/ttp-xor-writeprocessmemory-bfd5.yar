rule TTP_XOR_WriteProcessMemory_bfd5 {
  strings:
    $key_bfd5 = { e8 a7 [2] da 85 [2] dc b0 [2] f2 b0 [2] cd ac }

  condition:
    any of them
}