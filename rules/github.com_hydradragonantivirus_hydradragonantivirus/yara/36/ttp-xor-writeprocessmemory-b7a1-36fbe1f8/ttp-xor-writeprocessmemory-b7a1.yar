rule TTP_XOR_WriteProcessMemory_b7a1 {
  strings:
    $key_b7a1 = { e0 d3 [2] d2 f1 [2] d4 c4 [2] fa c4 [2] c5 d8 }

  condition:
    any of them
}