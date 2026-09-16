rule TTP_XOR_WriteProcessMemory_18fb {
  strings:
    $key_18fb = { 4f 89 [2] 7d ab [2] 7b 9e [2] 55 9e [2] 6a 82 }

  condition:
    any of them
}