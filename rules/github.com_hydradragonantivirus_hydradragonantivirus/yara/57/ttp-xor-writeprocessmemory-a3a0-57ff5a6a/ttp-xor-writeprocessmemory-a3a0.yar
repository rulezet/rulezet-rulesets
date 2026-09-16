rule TTP_XOR_WriteProcessMemory_a3a0 {
  strings:
    $key_a3a0 = { f4 d2 [2] c6 f0 [2] c0 c5 [2] ee c5 [2] d1 d9 }

  condition:
    any of them
}