rule TTP_XOR_WriteProcessMemory_69fb {
  strings:
    $key_69fb = { 3e 89 [2] 0c ab [2] 0a 9e [2] 24 9e [2] 1b 82 }

  condition:
    any of them
}