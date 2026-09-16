rule TTP_XOR_WriteProcessMemory_c5fb {
  strings:
    $key_c5fb = { 92 89 [2] a0 ab [2] a6 9e [2] 88 9e [2] b7 82 }

  condition:
    any of them
}