rule TTP_XOR_WriteProcessMemory_54a1 {
  strings:
    $key_54a1 = { 03 d3 [2] 31 f1 [2] 37 c4 [2] 19 c4 [2] 26 d8 }

  condition:
    any of them
}