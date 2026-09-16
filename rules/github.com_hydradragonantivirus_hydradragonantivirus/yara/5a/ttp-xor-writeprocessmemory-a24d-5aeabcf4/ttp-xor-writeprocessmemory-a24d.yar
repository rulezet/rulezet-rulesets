rule TTP_XOR_WriteProcessMemory_a24d {
  strings:
    $key_a24d = { f5 3f [2] c7 1d [2] c1 28 [2] ef 28 [2] d0 34 }

  condition:
    any of them
}