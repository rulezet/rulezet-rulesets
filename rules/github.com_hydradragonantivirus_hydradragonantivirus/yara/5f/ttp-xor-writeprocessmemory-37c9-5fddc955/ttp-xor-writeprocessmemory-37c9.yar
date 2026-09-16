rule TTP_XOR_WriteProcessMemory_37c9 {
  strings:
    $key_37c9 = { 60 bb [2] 52 99 [2] 54 ac [2] 7a ac [2] 45 b0 }

  condition:
    any of them
}