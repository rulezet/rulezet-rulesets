rule TTP_XOR_WriteProcessMemory_a5fb {
  strings:
    $key_a5fb = { f2 89 [2] c0 ab [2] c6 9e [2] e8 9e [2] d7 82 }

  condition:
    any of them
}