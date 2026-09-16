rule TTP_XOR_WriteProcessMemory_d3a6 {
  strings:
    $key_d3a6 = { 84 d4 [2] b6 f6 [2] b0 c3 [2] 9e c3 [2] a1 df }

  condition:
    any of them
}