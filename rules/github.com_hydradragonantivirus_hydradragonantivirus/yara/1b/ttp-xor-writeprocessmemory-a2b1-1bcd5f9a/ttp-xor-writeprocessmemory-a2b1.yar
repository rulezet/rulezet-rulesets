rule TTP_XOR_WriteProcessMemory_a2b1 {
  strings:
    $key_a2b1 = { f5 c3 [2] c7 e1 [2] c1 d4 [2] ef d4 [2] d0 c8 }

  condition:
    any of them
}