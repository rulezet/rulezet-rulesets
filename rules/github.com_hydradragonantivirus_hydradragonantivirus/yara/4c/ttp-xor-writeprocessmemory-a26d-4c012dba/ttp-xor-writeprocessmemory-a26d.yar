rule TTP_XOR_WriteProcessMemory_a26d {
  strings:
    $key_a26d = { f5 1f [2] c7 3d [2] c1 08 [2] ef 08 [2] d0 14 }

  condition:
    any of them
}