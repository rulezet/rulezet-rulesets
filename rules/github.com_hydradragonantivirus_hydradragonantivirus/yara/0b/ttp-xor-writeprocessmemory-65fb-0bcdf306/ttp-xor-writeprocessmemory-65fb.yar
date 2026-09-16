rule TTP_XOR_WriteProcessMemory_65fb {
  strings:
    $key_65fb = { 32 89 [2] 00 ab [2] 06 9e [2] 28 9e [2] 17 82 }

  condition:
    any of them
}