rule TTP_XOR_WriteProcessMemory_a250 {
  strings:
    $key_a250 = { f5 22 [2] c7 00 [2] c1 35 [2] ef 35 [2] d0 29 }

  condition:
    any of them
}