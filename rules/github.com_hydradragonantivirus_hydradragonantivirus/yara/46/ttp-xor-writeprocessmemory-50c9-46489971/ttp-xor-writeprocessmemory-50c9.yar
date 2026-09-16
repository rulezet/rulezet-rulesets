rule TTP_XOR_WriteProcessMemory_50c9 {
  strings:
    $key_50c9 = { 07 bb [2] 35 99 [2] 33 ac [2] 1d ac [2] 22 b0 }

  condition:
    any of them
}