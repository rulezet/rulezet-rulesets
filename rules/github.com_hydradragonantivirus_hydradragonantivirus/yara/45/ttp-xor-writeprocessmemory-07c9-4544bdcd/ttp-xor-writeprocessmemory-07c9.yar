rule TTP_XOR_WriteProcessMemory_07c9 {
  strings:
    $key_07c9 = { 50 bb [2] 62 99 [2] 64 ac [2] 4a ac [2] 75 b0 }

  condition:
    any of them
}