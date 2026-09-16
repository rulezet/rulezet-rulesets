rule TTP_XOR_WriteProcessMemory_01fb {
  strings:
    $key_01fb = { 56 89 [2] 64 ab [2] 62 9e [2] 4c 9e [2] 73 82 }

  condition:
    any of them
}