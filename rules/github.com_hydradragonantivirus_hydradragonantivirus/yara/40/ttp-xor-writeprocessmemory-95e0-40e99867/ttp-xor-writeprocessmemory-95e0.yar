rule TTP_XOR_WriteProcessMemory_95e0 {
  strings:
    $key_95e0 = { c2 92 [2] f0 b0 [2] f6 85 [2] d8 85 [2] e7 99 }

  condition:
    any of them
}