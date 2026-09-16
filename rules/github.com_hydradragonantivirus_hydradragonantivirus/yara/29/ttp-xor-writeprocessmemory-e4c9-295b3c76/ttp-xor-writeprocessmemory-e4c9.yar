rule TTP_XOR_WriteProcessMemory_e4c9 {
  strings:
    $key_e4c9 = { b3 bb [2] 81 99 [2] 87 ac [2] a9 ac [2] 96 b0 }

  condition:
    any of them
}