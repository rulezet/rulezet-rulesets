rule TTP_XOR_WriteProcessMemory_38fb {
  strings:
    $key_38fb = { 6f 89 [2] 5d ab [2] 5b 9e [2] 75 9e [2] 4a 82 }

  condition:
    any of them
}