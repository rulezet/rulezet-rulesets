rule TTP_XOR_WriteProcessMemory_a241 {
  strings:
    $key_a241 = { f5 33 [2] c7 11 [2] c1 24 [2] ef 24 [2] d0 38 }

  condition:
    any of them
}