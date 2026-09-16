rule TTP_XOR_WriteProcessMemory_a261 {
  strings:
    $key_a261 = { f5 13 [2] c7 31 [2] c1 04 [2] ef 04 [2] d0 18 }

  condition:
    any of them
}