rule TTP_XOR_WriteProcessMemory_a7a3 {
  strings:
    $key_a7a3 = { f0 d1 [2] c2 f3 [2] c4 c6 [2] ea c6 [2] d5 da }

  condition:
    any of them
}