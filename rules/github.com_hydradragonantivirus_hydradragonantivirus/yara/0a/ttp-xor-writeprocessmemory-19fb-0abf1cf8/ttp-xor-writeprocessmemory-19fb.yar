rule TTP_XOR_WriteProcessMemory_19fb {
  strings:
    $key_19fb = { 4e 89 [2] 7c ab [2] 7a 9e [2] 54 9e [2] 6b 82 }

  condition:
    any of them
}