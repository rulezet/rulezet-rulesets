rule TTP_XOR_WriteProcessMemory_c1a1 {
  strings:
    $key_c1a1 = { 96 d3 [2] a4 f1 [2] a2 c4 [2] 8c c4 [2] b3 d8 }

  condition:
    any of them
}