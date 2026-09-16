rule TTP_XOR_WriteProcessMemory_95b1 {
  strings:
    $key_95b1 = { c2 c3 [2] f0 e1 [2] f6 d4 [2] d8 d4 [2] e7 c8 }

  condition:
    any of them
}