rule TTP_XOR_WriteProcessMemory_a2f1 {
  strings:
    $key_a2f1 = { f5 83 [2] c7 a1 [2] c1 94 [2] ef 94 [2] d0 88 }

  condition:
    any of them
}