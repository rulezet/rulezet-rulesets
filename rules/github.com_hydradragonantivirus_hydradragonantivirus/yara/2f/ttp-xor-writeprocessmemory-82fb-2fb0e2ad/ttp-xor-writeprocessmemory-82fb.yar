rule TTP_XOR_WriteProcessMemory_82fb {
  strings:
    $key_82fb = { d5 89 [2] e7 ab [2] e1 9e [2] cf 9e [2] f0 82 }

  condition:
    any of them
}