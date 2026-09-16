rule TTP_XOR_WriteProcessMemory_b3b1 {
  strings:
    $key_b3b1 = { e4 c3 [2] d6 e1 [2] d0 d4 [2] fe d4 [2] c1 c8 }

  condition:
    any of them
}