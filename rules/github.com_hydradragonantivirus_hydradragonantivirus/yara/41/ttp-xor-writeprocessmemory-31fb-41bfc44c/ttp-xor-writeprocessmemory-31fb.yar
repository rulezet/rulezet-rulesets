rule TTP_XOR_WriteProcessMemory_31fb {
  strings:
    $key_31fb = { 66 89 [2] 54 ab [2] 52 9e [2] 7c 9e [2] 43 82 }

  condition:
    any of them
}