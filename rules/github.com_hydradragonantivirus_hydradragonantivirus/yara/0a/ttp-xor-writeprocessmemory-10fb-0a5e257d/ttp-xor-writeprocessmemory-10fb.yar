rule TTP_XOR_WriteProcessMemory_10fb {
  strings:
    $key_10fb = { 47 89 [2] 75 ab [2] 73 9e [2] 5d 9e [2] 62 82 }

  condition:
    any of them
}