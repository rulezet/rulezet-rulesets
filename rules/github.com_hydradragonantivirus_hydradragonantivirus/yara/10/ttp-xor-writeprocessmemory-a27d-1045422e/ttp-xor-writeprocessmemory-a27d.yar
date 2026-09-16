rule TTP_XOR_WriteProcessMemory_a27d {
  strings:
    $key_a27d = { f5 0f [2] c7 2d [2] c1 18 [2] ef 18 [2] d0 04 }

  condition:
    any of them
}