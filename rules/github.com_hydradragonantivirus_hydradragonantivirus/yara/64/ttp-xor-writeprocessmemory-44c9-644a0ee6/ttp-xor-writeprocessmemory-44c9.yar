rule TTP_XOR_WriteProcessMemory_44c9 {
  strings:
    $key_44c9 = { 13 bb [2] 21 99 [2] 27 ac [2] 09 ac [2] 36 b0 }

  condition:
    any of them
}