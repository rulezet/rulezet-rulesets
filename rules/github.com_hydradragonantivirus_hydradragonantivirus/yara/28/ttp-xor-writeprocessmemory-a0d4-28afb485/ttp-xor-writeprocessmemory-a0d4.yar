rule TTP_XOR_WriteProcessMemory_a0d4 {
  strings:
    $key_a0d4 = { f7 a6 [2] c5 84 [2] c3 b1 [2] ed b1 [2] d2 ad }

  condition:
    any of them
}