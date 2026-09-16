rule TTP_XOR_WriteProcessMemory_a2fb {
  strings:
    $key_a2fb = { f5 89 [2] c7 ab [2] c1 9e [2] ef 9e [2] d0 82 }

  condition:
    any of them
}