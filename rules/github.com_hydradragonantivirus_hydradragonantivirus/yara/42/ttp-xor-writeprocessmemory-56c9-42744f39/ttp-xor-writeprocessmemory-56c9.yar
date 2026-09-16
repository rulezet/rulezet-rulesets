rule TTP_XOR_WriteProcessMemory_56c9 {
  strings:
    $key_56c9 = { 01 bb [2] 33 99 [2] 35 ac [2] 1b ac [2] 24 b0 }

  condition:
    any of them
}