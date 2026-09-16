rule TTP_XOR_WriteProcessMemory_7881 {
  strings:
    $key_7881 = { 2f f3 [2] 1d d1 [2] 1b e4 [2] 35 e4 [2] 0a f8 }

  condition:
    any of them
}