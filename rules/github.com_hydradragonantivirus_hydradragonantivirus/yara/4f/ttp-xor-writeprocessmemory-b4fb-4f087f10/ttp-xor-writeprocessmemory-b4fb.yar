rule TTP_XOR_WriteProcessMemory_b4fb {
  strings:
    $key_b4fb = { e3 89 [2] d1 ab [2] d7 9e [2] f9 9e [2] c6 82 }

  condition:
    any of them
}