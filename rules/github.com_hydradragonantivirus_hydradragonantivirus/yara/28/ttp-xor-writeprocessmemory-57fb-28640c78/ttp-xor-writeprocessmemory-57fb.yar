rule TTP_XOR_WriteProcessMemory_57fb {
  strings:
    $key_57fb = { 00 89 [2] 32 ab [2] 34 9e [2] 1a 9e [2] 25 82 }

  condition:
    any of them
}