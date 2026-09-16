rule TTP_XOR_WriteProcessMemory_50fb {
  strings:
    $key_50fb = { 07 89 [2] 35 ab [2] 33 9e [2] 1d 9e [2] 22 82 }

  condition:
    any of them
}