rule TTP_XOR_WriteProcessMemory_d8fb {
  strings:
    $key_d8fb = { 8f 89 [2] bd ab [2] bb 9e [2] 95 9e [2] aa 82 }

  condition:
    any of them
}