rule TTP_XOR_WriteProcessMemory_4ba1 {
  strings:
    $key_4ba1 = { 1c d3 [2] 2e f1 [2] 28 c4 [2] 06 c4 [2] 39 d8 }

  condition:
    any of them
}