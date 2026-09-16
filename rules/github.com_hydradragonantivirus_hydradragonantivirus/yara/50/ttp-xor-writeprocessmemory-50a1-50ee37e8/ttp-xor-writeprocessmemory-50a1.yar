rule TTP_XOR_WriteProcessMemory_50a1 {
  strings:
    $key_50a1 = { 07 d3 [2] 35 f1 [2] 33 c4 [2] 1d c4 [2] 22 d8 }

  condition:
    any of them
}