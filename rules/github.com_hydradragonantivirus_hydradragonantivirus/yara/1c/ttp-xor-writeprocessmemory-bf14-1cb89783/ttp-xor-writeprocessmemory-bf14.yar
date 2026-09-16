rule TTP_XOR_WriteProcessMemory_bf14 {
  strings:
    $key_bf14 = { e8 66 [2] da 44 [2] dc 71 [2] f2 71 [2] cd 6d }

  condition:
    any of them
}