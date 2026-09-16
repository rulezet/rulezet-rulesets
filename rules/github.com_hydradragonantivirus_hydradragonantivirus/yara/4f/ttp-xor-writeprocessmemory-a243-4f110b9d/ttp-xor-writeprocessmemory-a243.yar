rule TTP_XOR_WriteProcessMemory_a243 {
  strings:
    $key_a243 = { f5 31 [2] c7 13 [2] c1 26 [2] ef 26 [2] d0 3a }

  condition:
    any of them
}