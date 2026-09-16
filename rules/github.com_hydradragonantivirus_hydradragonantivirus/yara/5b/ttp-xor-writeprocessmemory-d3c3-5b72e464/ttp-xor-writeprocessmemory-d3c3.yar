rule TTP_XOR_WriteProcessMemory_d3c3 {
  strings:
    $key_d3c3 = { 84 b1 [2] b6 93 [2] b0 a6 [2] 9e a6 [2] a1 ba }

  condition:
    any of them
}