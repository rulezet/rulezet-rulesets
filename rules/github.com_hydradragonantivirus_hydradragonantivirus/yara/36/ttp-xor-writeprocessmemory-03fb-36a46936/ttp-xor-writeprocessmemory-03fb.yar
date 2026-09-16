rule TTP_XOR_WriteProcessMemory_03fb {
  strings:
    $key_03fb = { 54 89 [2] 66 ab [2] 60 9e [2] 4e 9e [2] 71 82 }

  condition:
    any of them
}