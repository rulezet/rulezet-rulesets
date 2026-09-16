rule TTP_XOR_WriteProcessMemory_56fb {
  strings:
    $key_56fb = { 01 89 [2] 33 ab [2] 35 9e [2] 1b 9e [2] 24 82 }

  condition:
    any of them
}