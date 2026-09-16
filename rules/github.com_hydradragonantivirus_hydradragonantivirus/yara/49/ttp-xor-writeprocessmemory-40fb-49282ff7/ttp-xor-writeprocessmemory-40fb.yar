rule TTP_XOR_WriteProcessMemory_40fb {
  strings:
    $key_40fb = { 17 89 [2] 25 ab [2] 23 9e [2] 0d 9e [2] 32 82 }

  condition:
    any of them
}