rule TTP_XOR_WriteProcessMemory_bf97 {
  strings:
    $key_bf97 = { e8 e5 [2] da c7 [2] dc f2 [2] f2 f2 [2] cd ee }

  condition:
    any of them
}