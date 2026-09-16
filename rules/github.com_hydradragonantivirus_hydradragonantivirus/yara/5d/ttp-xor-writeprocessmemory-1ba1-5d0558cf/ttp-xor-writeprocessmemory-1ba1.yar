rule TTP_XOR_WriteProcessMemory_1ba1 {
  strings:
    $key_1ba1 = { 4c d3 [2] 7e f1 [2] 78 c4 [2] 56 c4 [2] 69 d8 }

  condition:
    any of them
}