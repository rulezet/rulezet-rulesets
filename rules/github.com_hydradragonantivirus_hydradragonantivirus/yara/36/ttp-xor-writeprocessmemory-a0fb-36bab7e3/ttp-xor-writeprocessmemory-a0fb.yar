rule TTP_XOR_WriteProcessMemory_a0fb {
  strings:
    $key_a0fb = { f7 89 [2] c5 ab [2] c3 9e [2] ed 9e [2] d2 82 }

  condition:
    any of them
}