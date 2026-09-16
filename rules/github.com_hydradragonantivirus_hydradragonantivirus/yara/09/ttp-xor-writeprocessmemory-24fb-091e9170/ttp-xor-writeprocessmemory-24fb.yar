rule TTP_XOR_WriteProcessMemory_24fb {
  strings:
    $key_24fb = { 73 89 [2] 41 ab [2] 47 9e [2] 69 9e [2] 56 82 }

  condition:
    any of them
}