rule TTP_XOR_WriteProcessMemory_b3a3 {
  strings:
    $key_b3a3 = { e4 d1 [2] d6 f3 [2] d0 c6 [2] fe c6 [2] c1 da }

  condition:
    any of them
}