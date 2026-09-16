rule TTP_XOR_WriteProcessMemory_a2f8 {
  strings:
    $key_a2f8 = { f5 8a [2] c7 a8 [2] c1 9d [2] ef 9d [2] d0 81 }

  condition:
    any of them
}