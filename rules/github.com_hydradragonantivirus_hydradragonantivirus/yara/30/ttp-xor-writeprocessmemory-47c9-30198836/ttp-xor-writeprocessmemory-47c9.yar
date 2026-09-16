rule TTP_XOR_WriteProcessMemory_47c9 {
  strings:
    $key_47c9 = { 10 bb [2] 22 99 [2] 24 ac [2] 0a ac [2] 35 b0 }

  condition:
    any of them
}