rule TTP_XOR_WriteProcessMemory_0ba1 {
  strings:
    $key_0ba1 = { 5c d3 [2] 6e f1 [2] 68 c4 [2] 46 c4 [2] 79 d8 }

  condition:
    any of them
}