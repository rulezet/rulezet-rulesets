rule TTP_XOR_WriteProcessMemory_6fc9 {
  strings:
    $key_6fc9 = { 38 bb [2] 0a 99 [2] 0c ac [2] 22 ac [2] 1d b0 }

  condition:
    any of them
}