rule TTP_XOR_WriteProcessMemory_bf81 {
  strings:
    $key_bf81 = { e8 f3 [2] da d1 [2] dc e4 [2] f2 e4 [2] cd f8 }

  condition:
    any of them
}