rule TTP_XOR_WriteProcessMemory_a7d6 {
  strings:
    $key_a7d6 = { f0 a4 [2] c2 86 [2] c4 b3 [2] ea b3 [2] d5 af }

  condition:
    any of them
}