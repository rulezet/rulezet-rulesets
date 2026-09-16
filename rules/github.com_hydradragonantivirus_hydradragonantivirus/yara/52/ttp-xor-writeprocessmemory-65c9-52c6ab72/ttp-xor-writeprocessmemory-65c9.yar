rule TTP_XOR_WriteProcessMemory_65c9 {
  strings:
    $key_65c9 = { 32 bb [2] 00 99 [2] 06 ac [2] 28 ac [2] 17 b0 }

  condition:
    any of them
}