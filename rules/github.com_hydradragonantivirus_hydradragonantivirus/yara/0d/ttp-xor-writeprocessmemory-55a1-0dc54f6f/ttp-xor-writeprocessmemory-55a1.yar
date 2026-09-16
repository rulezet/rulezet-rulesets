rule TTP_XOR_WriteProcessMemory_55a1 {
  strings:
    $key_55a1 = { 02 d3 [2] 30 f1 [2] 36 c4 [2] 18 c4 [2] 27 d8 }

  condition:
    any of them
}