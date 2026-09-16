rule TTP_XOR_WriteProcessMemory_d1fb {
  strings:
    $key_d1fb = { 86 89 [2] b4 ab [2] b2 9e [2] 9c 9e [2] a3 82 }

  condition:
    any of them
}