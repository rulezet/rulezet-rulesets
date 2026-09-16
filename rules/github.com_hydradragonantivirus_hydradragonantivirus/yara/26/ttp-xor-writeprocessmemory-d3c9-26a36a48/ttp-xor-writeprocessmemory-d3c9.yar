rule TTP_XOR_WriteProcessMemory_d3c9 {
  strings:
    $key_d3c9 = { 84 bb [2] b6 99 [2] b0 ac [2] 9e ac [2] a1 b0 }

  condition:
    any of them
}