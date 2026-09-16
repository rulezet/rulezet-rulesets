rule TTP_XOR_WriteProcessMemory_e0fb {
  strings:
    $key_e0fb = { b7 89 [2] 85 ab [2] 83 9e [2] ad 9e [2] 92 82 }

  condition:
    any of them
}