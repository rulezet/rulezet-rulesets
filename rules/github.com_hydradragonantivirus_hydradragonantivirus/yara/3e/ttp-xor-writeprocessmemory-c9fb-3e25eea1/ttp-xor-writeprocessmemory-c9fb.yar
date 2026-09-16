rule TTP_XOR_WriteProcessMemory_c9fb {
  strings:
    $key_c9fb = { 9e 89 [2] ac ab [2] aa 9e [2] 84 9e [2] bb 82 }

  condition:
    any of them
}