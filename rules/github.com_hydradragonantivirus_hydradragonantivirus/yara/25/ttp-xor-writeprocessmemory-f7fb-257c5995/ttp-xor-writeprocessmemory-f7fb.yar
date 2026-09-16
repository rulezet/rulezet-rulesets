rule TTP_XOR_WriteProcessMemory_f7fb {
  strings:
    $key_f7fb = { a0 89 [2] 92 ab [2] 94 9e [2] ba 9e [2] 85 82 }

  condition:
    any of them
}