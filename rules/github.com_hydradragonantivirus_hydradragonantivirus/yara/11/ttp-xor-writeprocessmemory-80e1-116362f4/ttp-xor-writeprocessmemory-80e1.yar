rule TTP_XOR_WriteProcessMemory_80e1 {
  strings:
    $key_80e1 = { d7 93 [2] e5 b1 [2] e3 84 [2] cd 84 [2] f2 98 }

  condition:
    any of them
}