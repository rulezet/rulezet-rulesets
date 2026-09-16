rule TTP_XOR_WriteProcessMemory_25fb {
  strings:
    $key_25fb = { 72 89 [2] 40 ab [2] 46 9e [2] 68 9e [2] 57 82 }

  condition:
    any of them
}