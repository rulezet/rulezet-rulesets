rule TTP_XOR_WriteProcessMemory_f0fb {
  strings:
    $key_f0fb = { a7 89 [2] 95 ab [2] 93 9e [2] bd 9e [2] 82 82 }

  condition:
    any of them
}