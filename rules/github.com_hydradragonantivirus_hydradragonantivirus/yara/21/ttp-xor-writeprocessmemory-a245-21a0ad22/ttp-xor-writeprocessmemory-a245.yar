rule TTP_XOR_WriteProcessMemory_a245 {
  strings:
    $key_a245 = { f5 37 [2] c7 15 [2] c1 20 [2] ef 20 [2] d0 3c }

  condition:
    any of them
}