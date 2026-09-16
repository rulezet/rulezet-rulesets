rule TTP_XOR_WriteProcessMemory_0fc9 {
  strings:
    $key_0fc9 = { 58 bb [2] 6a 99 [2] 6c ac [2] 42 ac [2] 7d b0 }

  condition:
    any of them
}