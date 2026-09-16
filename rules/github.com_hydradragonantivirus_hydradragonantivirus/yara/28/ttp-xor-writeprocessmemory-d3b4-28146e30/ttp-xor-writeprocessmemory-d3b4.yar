rule TTP_XOR_WriteProcessMemory_d3b4 {
  strings:
    $key_d3b4 = { 84 c6 [2] b6 e4 [2] b0 d1 [2] 9e d1 [2] a1 cd }

  condition:
    any of them
}