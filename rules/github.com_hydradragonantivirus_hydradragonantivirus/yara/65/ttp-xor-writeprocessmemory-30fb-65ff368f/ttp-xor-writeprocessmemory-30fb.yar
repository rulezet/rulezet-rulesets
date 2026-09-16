rule TTP_XOR_WriteProcessMemory_30fb {
  strings:
    $key_30fb = { 67 89 [2] 55 ab [2] 53 9e [2] 7d 9e [2] 42 82 }

  condition:
    any of them
}