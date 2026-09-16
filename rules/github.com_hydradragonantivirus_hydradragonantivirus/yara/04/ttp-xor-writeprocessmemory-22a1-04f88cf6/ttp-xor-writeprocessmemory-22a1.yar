rule TTP_XOR_WriteProcessMemory_22a1 {
  strings:
    $key_22a1 = { 75 d3 [2] 47 f1 [2] 41 c4 [2] 6f c4 [2] 50 d8 }

  condition:
    any of them
}