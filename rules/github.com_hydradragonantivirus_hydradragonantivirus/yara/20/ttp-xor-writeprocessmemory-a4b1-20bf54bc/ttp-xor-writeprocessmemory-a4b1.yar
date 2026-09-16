rule TTP_XOR_WriteProcessMemory_a4b1 {
  strings:
    $key_a4b1 = { f3 c3 [2] c1 e1 [2] c7 d4 [2] e9 d4 [2] d6 c8 }

  condition:
    any of them
}