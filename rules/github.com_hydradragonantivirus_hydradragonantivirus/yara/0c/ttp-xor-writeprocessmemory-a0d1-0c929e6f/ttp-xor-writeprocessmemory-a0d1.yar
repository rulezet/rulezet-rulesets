rule TTP_XOR_WriteProcessMemory_a0d1 {
  strings:
    $key_a0d1 = { f7 a3 [2] c5 81 [2] c3 b4 [2] ed b4 [2] d2 a8 }

  condition:
    any of them
}