rule TTP_XOR_WriteProcessMemory_a2b0 {
  strings:
    $key_a2b0 = { f5 c2 [2] c7 e0 [2] c1 d5 [2] ef d5 [2] d0 c9 }

  condition:
    any of them
}