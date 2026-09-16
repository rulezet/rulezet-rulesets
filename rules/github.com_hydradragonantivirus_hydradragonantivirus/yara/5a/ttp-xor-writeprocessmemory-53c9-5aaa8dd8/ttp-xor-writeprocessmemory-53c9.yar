rule TTP_XOR_WriteProcessMemory_53c9 {
  strings:
    $key_53c9 = { 04 bb [2] 36 99 [2] 30 ac [2] 1e ac [2] 21 b0 }

  condition:
    any of them
}