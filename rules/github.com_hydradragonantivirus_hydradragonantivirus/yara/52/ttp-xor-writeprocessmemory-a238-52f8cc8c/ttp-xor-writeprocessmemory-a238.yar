rule TTP_XOR_WriteProcessMemory_a238 {
  strings:
    $key_a238 = { f5 4a [2] c7 68 [2] c1 5d [2] ef 5d [2] d0 41 }

  condition:
    any of them
}