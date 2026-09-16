rule TTP_XOR_WriteProcessMemory_21fb {
  strings:
    $key_21fb = { 76 89 [2] 44 ab [2] 42 9e [2] 6c 9e [2] 53 82 }

  condition:
    any of them
}