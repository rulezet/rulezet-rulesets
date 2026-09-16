rule TTP_XOR_WriteProcessMemory_b7a0 {
  strings:
    $key_b7a0 = { e0 d2 [2] d2 f0 [2] d4 c5 [2] fa c5 [2] c5 d9 }

  condition:
    any of them
}