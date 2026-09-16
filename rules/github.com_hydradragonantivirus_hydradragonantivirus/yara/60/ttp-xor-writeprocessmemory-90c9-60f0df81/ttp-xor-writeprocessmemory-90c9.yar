rule TTP_XOR_WriteProcessMemory_90c9 {
  strings:
    $key_90c9 = { c7 bb [2] f5 99 [2] f3 ac [2] dd ac [2] e2 b0 }

  condition:
    any of them
}