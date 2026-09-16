rule TTP_XOR_WriteProcessMemory_37fb {
  strings:
    $key_37fb = { 60 89 [2] 52 ab [2] 54 9e [2] 7a 9e [2] 45 82 }

  condition:
    any of them
}