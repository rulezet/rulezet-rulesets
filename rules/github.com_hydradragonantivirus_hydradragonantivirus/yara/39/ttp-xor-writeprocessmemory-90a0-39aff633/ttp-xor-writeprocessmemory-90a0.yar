rule TTP_XOR_WriteProcessMemory_90a0 {
  strings:
    $key_90a0 = { c7 d2 [2] f5 f0 [2] f3 c5 [2] dd c5 [2] e2 d9 }

  condition:
    any of them
}