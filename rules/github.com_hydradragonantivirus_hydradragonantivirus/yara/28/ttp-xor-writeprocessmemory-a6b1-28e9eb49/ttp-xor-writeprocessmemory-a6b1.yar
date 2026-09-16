rule TTP_XOR_WriteProcessMemory_a6b1 {
  strings:
    $key_a6b1 = { f1 c3 [2] c3 e1 [2] c5 d4 [2] eb d4 [2] d4 c8 }

  condition:
    any of them
}