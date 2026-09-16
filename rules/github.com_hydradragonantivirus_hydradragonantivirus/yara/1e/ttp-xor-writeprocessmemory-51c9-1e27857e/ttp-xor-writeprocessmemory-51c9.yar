rule TTP_XOR_WriteProcessMemory_51c9 {
  strings:
    $key_51c9 = { 06 bb [2] 34 99 [2] 32 ac [2] 1c ac [2] 23 b0 }

  condition:
    any of them
}