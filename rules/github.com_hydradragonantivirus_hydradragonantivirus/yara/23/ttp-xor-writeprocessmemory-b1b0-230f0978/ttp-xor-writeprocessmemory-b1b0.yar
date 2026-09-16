rule TTP_XOR_WriteProcessMemory_b1b0 {
  strings:
    $key_b1b0 = { e6 c2 [2] d4 e0 [2] d2 d5 [2] fc d5 [2] c3 c9 }

  condition:
    any of them
}