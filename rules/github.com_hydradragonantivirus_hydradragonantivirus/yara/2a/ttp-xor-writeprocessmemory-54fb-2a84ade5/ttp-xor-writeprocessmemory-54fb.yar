rule TTP_XOR_WriteProcessMemory_54fb {
  strings:
    $key_54fb = { 03 89 [2] 31 ab [2] 37 9e [2] 19 9e [2] 26 82 }

  condition:
    any of them
}