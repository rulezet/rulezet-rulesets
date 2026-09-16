rule TTP_XOR_WriteProcessMemory_75fb {
  strings:
    $key_75fb = { 22 89 [2] 10 ab [2] 16 9e [2] 38 9e [2] 07 82 }

  condition:
    any of them
}