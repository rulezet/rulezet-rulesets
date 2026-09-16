rule TTP_XOR_WriteProcessMemory_b1b1 {
  strings:
    $key_b1b1 = { e6 c3 [2] d4 e1 [2] d2 d4 [2] fc d4 [2] c3 c8 }

  condition:
    any of them
}