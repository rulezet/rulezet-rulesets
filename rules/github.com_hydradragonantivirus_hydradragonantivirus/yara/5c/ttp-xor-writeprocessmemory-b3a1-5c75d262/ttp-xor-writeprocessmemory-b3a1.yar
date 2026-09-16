rule TTP_XOR_WriteProcessMemory_b3a1 {
  strings:
    $key_b3a1 = { e4 d3 [2] d6 f1 [2] d0 c4 [2] fe c4 [2] c1 d8 }

  condition:
    any of them
}