rule TTP_XOR_WriteProcessMemory_4881 {
  strings:
    $key_4881 = { 1f f3 [2] 2d d1 [2] 2b e4 [2] 05 e4 [2] 3a f8 }

  condition:
    any of them
}