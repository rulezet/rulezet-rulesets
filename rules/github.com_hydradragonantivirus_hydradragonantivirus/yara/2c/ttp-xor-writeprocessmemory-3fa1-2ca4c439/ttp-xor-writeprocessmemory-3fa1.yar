rule TTP_XOR_WriteProcessMemory_3fa1 {
  strings:
    $key_3fa1 = { 68 d3 [2] 5a f1 [2] 5c c4 [2] 72 c4 [2] 4d d8 }

  condition:
    any of them
}