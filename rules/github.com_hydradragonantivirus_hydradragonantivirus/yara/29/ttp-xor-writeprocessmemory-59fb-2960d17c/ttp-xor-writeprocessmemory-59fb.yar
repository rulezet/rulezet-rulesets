rule TTP_XOR_WriteProcessMemory_59fb {
  strings:
    $key_59fb = { 0e 89 [2] 3c ab [2] 3a 9e [2] 14 9e [2] 2b 82 }

  condition:
    any of them
}