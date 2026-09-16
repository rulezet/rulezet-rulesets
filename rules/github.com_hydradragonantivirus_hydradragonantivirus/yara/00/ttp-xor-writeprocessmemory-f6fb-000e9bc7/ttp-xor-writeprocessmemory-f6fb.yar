rule TTP_XOR_WriteProcessMemory_f6fb {
  strings:
    $key_f6fb = { a1 89 [2] 93 ab [2] 95 9e [2] bb 9e [2] 84 82 }

  condition:
    any of them
}