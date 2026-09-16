rule TTP_XOR_WriteProcessMemory_bfc4 {
  strings:
    $key_bfc4 = { e8 b6 [2] da 94 [2] dc a1 [2] f2 a1 [2] cd bd }

  condition:
    any of them
}