rule TTP_XOR_WriteProcessMemory_27fb {
  strings:
    $key_27fb = { 70 89 [2] 42 ab [2] 44 9e [2] 6a 9e [2] 55 82 }

  condition:
    any of them
}