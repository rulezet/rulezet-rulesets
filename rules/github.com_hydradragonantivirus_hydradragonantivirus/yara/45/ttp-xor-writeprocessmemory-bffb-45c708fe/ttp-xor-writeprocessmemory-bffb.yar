rule TTP_XOR_WriteProcessMemory_bffb {
  strings:
    $key_bffb = { e8 89 [2] da ab [2] dc 9e [2] f2 9e [2] cd 82 }

  condition:
    any of them
}