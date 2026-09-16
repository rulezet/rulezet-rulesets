rule TTP_XOR_WriteProcessMemory_1fc9 {
  strings:
    $key_1fc9 = { 48 bb [2] 7a 99 [2] 7c ac [2] 52 ac [2] 6d b0 }

  condition:
    any of them
}