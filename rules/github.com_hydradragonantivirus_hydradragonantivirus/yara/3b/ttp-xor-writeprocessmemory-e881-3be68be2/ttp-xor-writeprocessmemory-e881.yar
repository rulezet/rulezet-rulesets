rule TTP_XOR_WriteProcessMemory_e881 {
  strings:
    $key_e881 = { bf f3 [2] 8d d1 [2] 8b e4 [2] a5 e4 [2] 9a f8 }

  condition:
    any of them
}