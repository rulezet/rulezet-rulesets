rule TTP_XOR_WriteProcessMemory_bea1 {
  strings:
    $key_bea1 = { e9 d3 [2] db f1 [2] dd c4 [2] f3 c4 [2] cc d8 }

  condition:
    any of them
}