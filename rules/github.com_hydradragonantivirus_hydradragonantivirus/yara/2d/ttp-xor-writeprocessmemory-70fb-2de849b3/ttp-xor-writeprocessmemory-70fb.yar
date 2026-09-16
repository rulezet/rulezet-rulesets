rule TTP_XOR_WriteProcessMemory_70fb {
  strings:
    $key_70fb = { 27 89 [2] 15 ab [2] 13 9e [2] 3d 9e [2] 02 82 }

  condition:
    any of them
}