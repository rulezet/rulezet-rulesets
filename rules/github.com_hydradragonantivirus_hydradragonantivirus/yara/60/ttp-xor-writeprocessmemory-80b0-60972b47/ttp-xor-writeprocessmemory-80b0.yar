rule TTP_XOR_WriteProcessMemory_80b0 {
  strings:
    $key_80b0 = { d7 c2 [2] e5 e0 [2] e3 d5 [2] cd d5 [2] f2 c9 }

  condition:
    any of them
}