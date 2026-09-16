rule TTP_XOR_WriteProcessMemory_17fb {
  strings:
    $key_17fb = { 40 89 [2] 72 ab [2] 74 9e [2] 5a 9e [2] 65 82 }

  condition:
    any of them
}