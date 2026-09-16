rule TTP_XOR_WriteProcessMemory_b1fb {
  strings:
    $key_b1fb = { e6 89 [2] d4 ab [2] d2 9e [2] fc 9e [2] c3 82 }

  condition:
    any of them
}