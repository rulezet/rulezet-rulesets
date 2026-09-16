rule TTP_XOR_WriteProcessMemory_57c9 {
  strings:
    $key_57c9 = { 00 bb [2] 32 99 [2] 34 ac [2] 1a ac [2] 25 b0 }

  condition:
    any of them
}