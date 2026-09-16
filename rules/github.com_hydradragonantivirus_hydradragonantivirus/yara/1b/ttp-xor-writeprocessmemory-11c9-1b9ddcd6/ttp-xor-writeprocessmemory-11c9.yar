rule TTP_XOR_WriteProcessMemory_11c9 {
  strings:
    $key_11c9 = { 46 bb [2] 74 99 [2] 72 ac [2] 5c ac [2] 63 b0 }

  condition:
    any of them
}