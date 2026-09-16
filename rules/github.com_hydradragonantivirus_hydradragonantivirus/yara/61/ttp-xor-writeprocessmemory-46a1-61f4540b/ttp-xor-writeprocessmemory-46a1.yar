rule TTP_XOR_WriteProcessMemory_46a1 {
  strings:
    $key_46a1 = { 11 d3 [2] 23 f1 [2] 25 c4 [2] 0b c4 [2] 34 d8 }

  condition:
    any of them
}