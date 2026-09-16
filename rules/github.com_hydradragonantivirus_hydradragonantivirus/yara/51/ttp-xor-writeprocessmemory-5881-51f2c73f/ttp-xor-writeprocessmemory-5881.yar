rule TTP_XOR_WriteProcessMemory_5881 {
  strings:
    $key_5881 = { 0f f3 [2] 3d d1 [2] 3b e4 [2] 15 e4 [2] 2a f8 }

  condition:
    any of them
}