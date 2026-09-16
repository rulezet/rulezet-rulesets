rule TTP_XOR_WriteProcessMemory_b0fb {
  strings:
    $key_b0fb = { e7 89 [2] d5 ab [2] d3 9e [2] fd 9e [2] c2 82 }

  condition:
    any of them
}