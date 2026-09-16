rule TTP_XOR_WriteProcessMemory_a3a6 {
  strings:
    $key_a3a6 = { f4 d4 [2] c6 f6 [2] c0 c3 [2] ee c3 [2] d1 df }

  condition:
    any of them
}