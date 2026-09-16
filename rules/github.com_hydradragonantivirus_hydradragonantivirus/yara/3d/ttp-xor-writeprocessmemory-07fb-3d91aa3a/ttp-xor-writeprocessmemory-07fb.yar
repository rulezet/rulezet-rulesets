rule TTP_XOR_WriteProcessMemory_07fb {
  strings:
    $key_07fb = { 50 89 [2] 62 ab [2] 64 9e [2] 4a 9e [2] 75 82 }

  condition:
    any of them
}