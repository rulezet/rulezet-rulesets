rule TTP_XOR_WriteProcessMemory_d3c4 {
  strings:
    $key_d3c4 = { 84 b6 [2] b6 94 [2] b0 a1 [2] 9e a1 [2] a1 bd }

  condition:
    any of them
}