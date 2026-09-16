rule TTP_XOR_WriteProcessMemory_80f0 {
  strings:
    $key_80f0 = { d7 82 [2] e5 a0 [2] e3 95 [2] cd 95 [2] f2 89 }

  condition:
    any of them
}