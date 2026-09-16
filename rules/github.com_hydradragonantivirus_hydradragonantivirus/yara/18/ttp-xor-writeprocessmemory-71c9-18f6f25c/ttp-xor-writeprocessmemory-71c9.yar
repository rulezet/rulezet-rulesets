rule TTP_XOR_WriteProcessMemory_71c9 {
  strings:
    $key_71c9 = { 26 bb [2] 14 99 [2] 12 ac [2] 3c ac [2] 03 b0 }

  condition:
    any of them
}