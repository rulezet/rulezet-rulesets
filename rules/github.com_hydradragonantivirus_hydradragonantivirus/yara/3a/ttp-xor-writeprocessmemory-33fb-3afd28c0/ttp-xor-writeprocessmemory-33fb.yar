rule TTP_XOR_WriteProcessMemory_33fb {
  strings:
    $key_33fb = { 64 89 [2] 56 ab [2] 50 9e [2] 7e 9e [2] 41 82 }

  condition:
    any of them
}