rule TTP_XOR_WriteProcessMemory_20fb {
  strings:
    $key_20fb = { 77 89 [2] 45 ab [2] 43 9e [2] 6d 9e [2] 52 82 }

  condition:
    any of them
}