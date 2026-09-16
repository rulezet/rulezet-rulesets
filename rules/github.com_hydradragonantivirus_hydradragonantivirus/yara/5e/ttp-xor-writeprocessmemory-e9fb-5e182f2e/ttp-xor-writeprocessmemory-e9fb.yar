rule TTP_XOR_WriteProcessMemory_e9fb {
  strings:
    $key_e9fb = { be 89 [2] 8c ab [2] 8a 9e [2] a4 9e [2] 9b 82 }

  condition:
    any of them
}