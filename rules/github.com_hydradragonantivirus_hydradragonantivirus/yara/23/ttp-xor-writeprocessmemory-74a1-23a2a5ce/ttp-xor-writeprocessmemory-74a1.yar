rule TTP_XOR_WriteProcessMemory_74a1 {
  strings:
    $key_74a1 = { 23 d3 [2] 11 f1 [2] 17 c4 [2] 39 c4 [2] 06 d8 }

  condition:
    any of them
}