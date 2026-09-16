rule TTP_XOR_WriteProcessMemory_c6fb {
  strings:
    $key_c6fb = { 91 89 [2] a3 ab [2] a5 9e [2] 8b 9e [2] b4 82 }

  condition:
    any of them
}