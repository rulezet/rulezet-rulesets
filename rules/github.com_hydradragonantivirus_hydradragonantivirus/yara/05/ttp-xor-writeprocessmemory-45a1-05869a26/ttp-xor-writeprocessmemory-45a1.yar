rule TTP_XOR_WriteProcessMemory_45a1 {
  strings:
    $key_45a1 = { 12 d3 [2] 20 f1 [2] 26 c4 [2] 08 c4 [2] 37 d8 }

  condition:
    any of them
}