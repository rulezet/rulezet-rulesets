rule TTP_XOR_WriteProcessMemory_d2fb {
  strings:
    $key_d2fb = { 85 89 [2] b7 ab [2] b1 9e [2] 9f 9e [2] a0 82 }

  condition:
    any of them
}