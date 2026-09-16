rule TTP_XOR_WriteProcessMemory_a7fb {
  strings:
    $key_a7fb = { f0 89 [2] c2 ab [2] c4 9e [2] ea 9e [2] d5 82 }

  condition:
    any of them
}