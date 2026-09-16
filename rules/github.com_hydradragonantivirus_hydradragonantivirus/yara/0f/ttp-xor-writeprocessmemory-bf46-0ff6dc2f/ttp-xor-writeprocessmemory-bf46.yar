rule TTP_XOR_WriteProcessMemory_bf46 {
  strings:
    $key_bf46 = { e8 34 [2] da 16 [2] dc 23 [2] f2 23 [2] cd 3f }

  condition:
    any of them
}