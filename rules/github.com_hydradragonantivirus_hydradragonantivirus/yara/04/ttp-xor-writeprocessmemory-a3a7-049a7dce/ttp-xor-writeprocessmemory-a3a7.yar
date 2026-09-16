rule TTP_XOR_WriteProcessMemory_a3a7 {
  strings:
    $key_a3a7 = { f4 d5 [2] c6 f7 [2] c0 c2 [2] ee c2 [2] d1 de }

  condition:
    any of them
}