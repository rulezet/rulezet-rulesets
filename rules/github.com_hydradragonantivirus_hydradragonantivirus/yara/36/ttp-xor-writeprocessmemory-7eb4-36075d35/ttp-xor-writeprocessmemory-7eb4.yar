rule TTP_XOR_WriteProcessMemory_7eb4 {
  strings:
    $key_7eb4 = { 29 c6 [2] 1b e4 [2] 1d d1 [2] 33 d1 [2] 0c cd }

  condition:
    any of them
}