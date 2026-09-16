rule TTP_XOR_WriteProcessMemory_e8fb {
  strings:
    $key_e8fb = { bf 89 [2] 8d ab [2] 8b 9e [2] a5 9e [2] 9a 82 }

  condition:
    any of them
}