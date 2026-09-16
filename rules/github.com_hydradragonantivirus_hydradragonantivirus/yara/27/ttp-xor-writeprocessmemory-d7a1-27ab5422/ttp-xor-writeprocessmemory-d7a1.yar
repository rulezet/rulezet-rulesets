rule TTP_XOR_WriteProcessMemory_d7a1 {
  strings:
    $key_d7a1 = { 80 d3 [2] b2 f1 [2] b4 c4 [2] 9a c4 [2] a5 d8 }

  condition:
    any of them
}