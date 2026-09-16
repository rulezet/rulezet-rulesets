rule TTP_XOR_WriteProcessMemory_c2a1 {
  strings:
    $key_c2a1 = { 95 d3 [2] a7 f1 [2] a1 c4 [2] 8f c4 [2] b0 d8 }

  condition:
    any of them
}