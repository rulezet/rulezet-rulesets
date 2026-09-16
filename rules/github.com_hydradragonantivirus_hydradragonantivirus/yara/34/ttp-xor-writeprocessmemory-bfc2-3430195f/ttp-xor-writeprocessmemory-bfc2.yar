rule TTP_XOR_WriteProcessMemory_bfc2 {
  strings:
    $key_bfc2 = { e8 b0 [2] da 92 [2] dc a7 [2] f2 a7 [2] cd bb }

  condition:
    any of them
}