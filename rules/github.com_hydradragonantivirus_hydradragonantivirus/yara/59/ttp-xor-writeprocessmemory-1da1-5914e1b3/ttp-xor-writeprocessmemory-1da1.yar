rule TTP_XOR_WriteProcessMemory_1da1 {
  strings:
    $key_1da1 = { 4a d3 [2] 78 f1 [2] 7e c4 [2] 50 c4 [2] 6f d8 }

  condition:
    any of them
}