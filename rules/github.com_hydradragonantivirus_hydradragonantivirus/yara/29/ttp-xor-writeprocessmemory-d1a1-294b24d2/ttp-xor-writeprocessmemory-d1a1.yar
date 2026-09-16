rule TTP_XOR_WriteProcessMemory_d1a1 {
  strings:
    $key_d1a1 = { 86 d3 [2] b4 f1 [2] b2 c4 [2] 9c c4 [2] a3 d8 }

  condition:
    any of them
}