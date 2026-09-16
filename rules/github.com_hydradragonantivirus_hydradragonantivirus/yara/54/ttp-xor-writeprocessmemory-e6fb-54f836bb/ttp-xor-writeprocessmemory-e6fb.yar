rule TTP_XOR_WriteProcessMemory_e6fb {
  strings:
    $key_e6fb = { b1 89 [2] 83 ab [2] 85 9e [2] ab 9e [2] 94 82 }

  condition:
    any of them
}