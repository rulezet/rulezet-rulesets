rule TTP_XOR_WriteProcessMemory_90a1 {
  strings:
    $key_90a1 = { c7 d3 [2] f5 f1 [2] f3 c4 [2] dd c4 [2] e2 d8 }

  condition:
    any of them
}