rule TTP_XOR_WriteProcessMemory_85fb {
  strings:
    $key_85fb = { d2 89 [2] e0 ab [2] e6 9e [2] c8 9e [2] f7 82 }

  condition:
    any of them
}