rule TTP_XOR_WriteProcessMemory_42a1 {
  strings:
    $key_42a1 = { 15 d3 [2] 27 f1 [2] 21 c4 [2] 0f c4 [2] 30 d8 }

  condition:
    any of them
}