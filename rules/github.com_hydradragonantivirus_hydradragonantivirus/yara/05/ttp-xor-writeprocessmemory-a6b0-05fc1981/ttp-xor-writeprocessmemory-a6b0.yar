rule TTP_XOR_WriteProcessMemory_a6b0 {
  strings:
    $key_a6b0 = { f1 c2 [2] c3 e0 [2] c5 d5 [2] eb d5 [2] d4 c9 }

  condition:
    any of them
}