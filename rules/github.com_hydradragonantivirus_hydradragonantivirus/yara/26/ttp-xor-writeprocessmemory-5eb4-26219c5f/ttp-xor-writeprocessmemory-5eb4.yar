rule TTP_XOR_WriteProcessMemory_5eb4 {
  strings:
    $key_5eb4 = { 09 c6 [2] 3b e4 [2] 3d d1 [2] 13 d1 [2] 2c cd }

  condition:
    any of them
}