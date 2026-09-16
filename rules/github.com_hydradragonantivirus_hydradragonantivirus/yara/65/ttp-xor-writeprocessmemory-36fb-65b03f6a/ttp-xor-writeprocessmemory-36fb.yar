rule TTP_XOR_WriteProcessMemory_36fb {
  strings:
    $key_36fb = { 61 89 [2] 53 ab [2] 55 9e [2] 7b 9e [2] 44 82 }

  condition:
    any of them
}