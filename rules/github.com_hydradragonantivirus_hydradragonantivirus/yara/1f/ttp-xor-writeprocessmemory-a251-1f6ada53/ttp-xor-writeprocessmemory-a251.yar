rule TTP_XOR_WriteProcessMemory_a251 {
  strings:
    $key_a251 = { f5 23 [2] c7 01 [2] c1 34 [2] ef 34 [2] d0 28 }

  condition:
    any of them
}