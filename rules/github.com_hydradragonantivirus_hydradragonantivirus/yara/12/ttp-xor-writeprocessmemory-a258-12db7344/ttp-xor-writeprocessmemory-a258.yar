rule TTP_XOR_WriteProcessMemory_a258 {
  strings:
    $key_a258 = { f5 2a [2] c7 08 [2] c1 3d [2] ef 3d [2] d0 21 }

  condition:
    any of them
}