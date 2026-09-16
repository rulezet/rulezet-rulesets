rule TTP_XOR_WriteProcessMemory_b3a5 {
  strings:
    $key_b3a5 = { e4 d7 [2] d6 f5 [2] d0 c0 [2] fe c0 [2] c1 dc }

  condition:
    any of them
}