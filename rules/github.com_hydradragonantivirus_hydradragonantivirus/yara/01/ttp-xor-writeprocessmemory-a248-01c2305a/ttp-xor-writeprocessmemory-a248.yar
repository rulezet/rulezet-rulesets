rule TTP_XOR_WriteProcessMemory_a248 {
  strings:
    $key_a248 = { f5 3a [2] c7 18 [2] c1 2d [2] ef 2d [2] d0 31 }

  condition:
    any of them
}