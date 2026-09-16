rule TTP_XOR_WriteProcessMemory_b3fb {
  strings:
    $key_b3fb = { e4 89 [2] d6 ab [2] d0 9e [2] fe 9e [2] c1 82 }

  condition:
    any of them
}