rule TTP_XOR_WriteProcessMemory_c1c9 {
  strings:
    $key_c1c9 = { 96 bb [2] a4 99 [2] a2 ac [2] 8c ac [2] b3 b0 }

  condition:
    any of them
}