rule TTP_XOR_WriteProcessMemory_bf64 {
  strings:
    $key_bf64 = { e8 16 [2] da 34 [2] dc 01 [2] f2 01 [2] cd 1d }

  condition:
    any of them
}