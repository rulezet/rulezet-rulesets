rule TTP_XOR_WriteProcessMemory_d6a1 {
  strings:
    $key_d6a1 = { 81 d3 [2] b3 f1 [2] b5 c4 [2] 9b c4 [2] a4 d8 }

  condition:
    any of them
}