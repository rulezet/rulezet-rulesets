rule TTP_XOR_WriteProcessMemory_7fc9 {
  strings:
    $key_7fc9 = { 28 bb [2] 1a 99 [2] 1c ac [2] 32 ac [2] 0d b0 }

  condition:
    any of them
}