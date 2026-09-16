rule TTP_XOR_WriteProcessMemory_5fa1 {
  strings:
    $key_5fa1 = { 08 d3 [2] 3a f1 [2] 3c c4 [2] 12 c4 [2] 2d d8 }

  condition:
    any of them
}