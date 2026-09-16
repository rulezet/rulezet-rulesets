rule TTP_XOR_WriteProcessMemory_a7d1 {
  strings:
    $key_a7d1 = { f0 a3 [2] c2 81 [2] c4 b4 [2] ea b4 [2] d5 a8 }

  condition:
    any of them
}