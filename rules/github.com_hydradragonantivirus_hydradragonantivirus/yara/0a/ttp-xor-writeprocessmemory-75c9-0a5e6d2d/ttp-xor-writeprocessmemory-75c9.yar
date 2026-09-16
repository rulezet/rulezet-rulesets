rule TTP_XOR_WriteProcessMemory_75c9 {
  strings:
    $key_75c9 = { 22 bb [2] 10 99 [2] 16 ac [2] 38 ac [2] 07 b0 }

  condition:
    any of them
}