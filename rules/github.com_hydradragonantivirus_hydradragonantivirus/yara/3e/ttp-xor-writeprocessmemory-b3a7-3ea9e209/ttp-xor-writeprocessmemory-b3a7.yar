rule TTP_XOR_WriteProcessMemory_b3a7 {
  strings:
    $key_b3a7 = { e4 d5 [2] d6 f7 [2] d0 c2 [2] fe c2 [2] c1 de }

  condition:
    any of them
}