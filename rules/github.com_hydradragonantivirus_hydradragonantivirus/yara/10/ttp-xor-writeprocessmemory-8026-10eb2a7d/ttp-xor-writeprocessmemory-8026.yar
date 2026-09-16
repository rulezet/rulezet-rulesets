rule TTP_XOR_WriteProcessMemory_8026 {
  strings:
    $key_8026 = { d7 54 [2] e5 76 [2] e3 43 [2] cd 43 [2] f2 5f }

  condition:
    any of them
}