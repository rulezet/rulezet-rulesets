rule TTP_XOR_WriteProcessMemory_95b0 {
  strings:
    $key_95b0 = { c2 c2 [2] f0 e0 [2] f6 d5 [2] d8 d5 [2] e7 c9 }

  condition:
    any of them
}