rule TTP_XOR_WriteProcessMemory_6fa1 {
  strings:
    $key_6fa1 = { 38 d3 [2] 0a f1 [2] 0c c4 [2] 22 c4 [2] 1d d8 }

  condition:
    any of them
}