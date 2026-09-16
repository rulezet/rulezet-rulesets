rule TTP_XOR_WriteProcessMemory_bf66 {
  strings:
    $key_bf66 = { e8 14 [2] da 36 [2] dc 03 [2] f2 03 [2] cd 1f }

  condition:
    any of them
}