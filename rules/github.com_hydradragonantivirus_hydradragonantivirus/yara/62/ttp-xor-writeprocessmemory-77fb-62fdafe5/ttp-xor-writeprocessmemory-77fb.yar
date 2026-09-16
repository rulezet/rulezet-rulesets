rule TTP_XOR_WriteProcessMemory_77fb {
  strings:
    $key_77fb = { 20 89 [2] 12 ab [2] 14 9e [2] 3a 9e [2] 05 82 }

  condition:
    any of them
}