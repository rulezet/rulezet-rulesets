rule TTP_XOR_WriteProcessMemory_43fb {
  strings:
    $key_43fb = { 14 89 [2] 26 ab [2] 20 9e [2] 0e 9e [2] 31 82 }

  condition:
    any of them
}