rule TTP_XOR_WriteProcessMemory_a2f0 {
  strings:
    $key_a2f0 = { f5 82 [2] c7 a0 [2] c1 95 [2] ef 95 [2] d0 89 }

  condition:
    any of them
}