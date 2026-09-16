rule TTP_XOR_WriteProcessMemory_d3a5 {
  strings:
    $key_d3a5 = { 84 d7 [2] b6 f5 [2] b0 c0 [2] 9e c0 [2] a1 dc }

  condition:
    any of them
}