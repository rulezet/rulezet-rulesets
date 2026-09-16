rule TTP_XOR_WriteProcessMemory_b3a6 {
  strings:
    $key_b3a6 = { e4 d4 [2] d6 f6 [2] d0 c3 [2] fe c3 [2] c1 df }

  condition:
    any of them
}