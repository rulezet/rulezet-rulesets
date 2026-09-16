rule TTP_XOR_WriteProcessMemory_6ba1 {
  strings:
    $key_6ba1 = { 3c d3 [2] 0e f1 [2] 08 c4 [2] 26 c4 [2] 19 d8 }

  condition:
    any of them
}