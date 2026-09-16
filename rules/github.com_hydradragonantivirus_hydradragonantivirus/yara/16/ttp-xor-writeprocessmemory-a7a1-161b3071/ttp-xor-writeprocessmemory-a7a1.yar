rule TTP_XOR_WriteProcessMemory_a7a1 {
  strings:
    $key_a7a1 = { f0 d3 [2] c2 f1 [2] c4 c4 [2] ea c4 [2] d5 d8 }

  condition:
    any of them
}