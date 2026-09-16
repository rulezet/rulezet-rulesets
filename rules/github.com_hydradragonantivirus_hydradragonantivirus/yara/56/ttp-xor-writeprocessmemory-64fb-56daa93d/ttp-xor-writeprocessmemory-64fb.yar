rule TTP_XOR_WriteProcessMemory_64fb {
  strings:
    $key_64fb = { 33 89 [2] 01 ab [2] 07 9e [2] 29 9e [2] 16 82 }

  condition:
    any of them
}