rule TTP_XOR_WriteProcessMemory_10c9 {
  strings:
    $key_10c9 = { 47 bb [2] 75 99 [2] 73 ac [2] 5d ac [2] 62 b0 }

  condition:
    any of them
}