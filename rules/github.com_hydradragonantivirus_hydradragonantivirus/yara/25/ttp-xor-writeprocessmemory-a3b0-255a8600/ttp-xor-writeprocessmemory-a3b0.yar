rule TTP_XOR_WriteProcessMemory_a3b0 {
  strings:
    $key_a3b0 = { f4 c2 [2] c6 e0 [2] c0 d5 [2] ee d5 [2] d1 c9 }

  condition:
    any of them
}