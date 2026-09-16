rule TTP_XOR_WriteProcessMemory_d3b3 {
  strings:
    $key_d3b3 = { 84 c1 [2] b6 e3 [2] b0 d6 [2] 9e d6 [2] a1 ca }

  condition:
    any of them
}