rule TTP_XOR_WriteProcessMemory_90fb {
  strings:
    $key_90fb = { c7 89 [2] f5 ab [2] f3 9e [2] dd 9e [2] e2 82 }

  condition:
    any of them
}