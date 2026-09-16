rule TTP_XOR_WriteProcessMemory_bfe2 {
  strings:
    $key_bfe2 = { e8 90 [2] da b2 [2] dc 87 [2] f2 87 [2] cd 9b }

  condition:
    any of them
}