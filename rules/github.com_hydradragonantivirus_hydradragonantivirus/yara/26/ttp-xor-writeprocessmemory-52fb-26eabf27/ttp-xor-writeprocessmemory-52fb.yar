rule TTP_XOR_WriteProcessMemory_52fb {
  strings:
    $key_52fb = { 05 89 [2] 37 ab [2] 31 9e [2] 1f 9e [2] 20 82 }

  condition:
    any of them
}