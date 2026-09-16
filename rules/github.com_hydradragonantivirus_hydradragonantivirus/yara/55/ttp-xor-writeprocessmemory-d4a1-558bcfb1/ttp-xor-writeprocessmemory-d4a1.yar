rule TTP_XOR_WriteProcessMemory_d4a1 {
  strings:
    $key_d4a1 = { 83 d3 [2] b1 f1 [2] b7 c4 [2] 99 c4 [2] a6 d8 }

  condition:
    any of them
}