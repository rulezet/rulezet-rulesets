rule TTP_XOR_WriteProcessMemory_c7a1 {
  strings:
    $key_c7a1 = { 90 d3 [2] a2 f1 [2] a4 c4 [2] 8a c4 [2] b5 d8 }

  condition:
    any of them
}