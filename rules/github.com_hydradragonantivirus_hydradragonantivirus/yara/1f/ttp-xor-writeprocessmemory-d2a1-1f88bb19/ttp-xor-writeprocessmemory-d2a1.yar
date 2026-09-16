rule TTP_XOR_WriteProcessMemory_d2a1 {
  strings:
    $key_d2a1 = { 85 d3 [2] b7 f1 [2] b1 c4 [2] 9f c4 [2] a0 d8 }

  condition:
    any of them
}