rule TTP_XOR_WriteProcessMemory_63fb {
  strings:
    $key_63fb = { 34 89 [2] 06 ab [2] 00 9e [2] 2e 9e [2] 11 82 }

  condition:
    any of them
}