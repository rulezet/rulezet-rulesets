rule TTP_XOR_WriteProcessMemory_29fb {
  strings:
    $key_29fb = { 7e 89 [2] 4c ab [2] 4a 9e [2] 64 9e [2] 5b 82 }

  condition:
    any of them
}