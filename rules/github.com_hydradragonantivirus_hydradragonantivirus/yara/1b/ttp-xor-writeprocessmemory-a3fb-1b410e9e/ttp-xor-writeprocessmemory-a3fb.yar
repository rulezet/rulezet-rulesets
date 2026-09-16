rule TTP_XOR_WriteProcessMemory_a3fb {
  strings:
    $key_a3fb = { f4 89 [2] c6 ab [2] c0 9e [2] ee 9e [2] d1 82 }

  condition:
    any of them
}