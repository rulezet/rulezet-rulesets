rule TTP_XOR_WriteProcessMemory_d3a3 {
  strings:
    $key_d3a3 = { 84 d1 [2] b6 f3 [2] b0 c6 [2] 9e c6 [2] a1 da }

  condition:
    any of them
}