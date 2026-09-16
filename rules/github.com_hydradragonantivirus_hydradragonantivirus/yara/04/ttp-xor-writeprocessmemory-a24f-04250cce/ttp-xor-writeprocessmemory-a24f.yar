rule TTP_XOR_WriteProcessMemory_a24f {
  strings:
    $key_a24f = { f5 3d [2] c7 1f [2] c1 2a [2] ef 2a [2] d0 36 }

  condition:
    any of them
}