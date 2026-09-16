rule TTP_XOR_WriteProcessMemory_a7b0 {
  strings:
    $key_a7b0 = { f0 c2 [2] c2 e0 [2] c4 d5 [2] ea d5 [2] d5 c9 }

  condition:
    any of them
}