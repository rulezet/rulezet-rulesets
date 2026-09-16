rule TTP_XOR_WriteProcessMemory_78a1 {
  strings:
    $key_78a1 = { 2f d3 [2] 1d f1 [2] 1b c4 [2] 35 c4 [2] 0a d8 }

  condition:
    any of them
}