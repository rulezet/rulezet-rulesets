rule TTP_XOR_WriteProcessMemory_d5c9 {
  strings:
    $key_d5c9 = { 82 bb [2] b0 99 [2] b6 ac [2] 98 ac [2] a7 b0 }

  condition:
    any of them
}