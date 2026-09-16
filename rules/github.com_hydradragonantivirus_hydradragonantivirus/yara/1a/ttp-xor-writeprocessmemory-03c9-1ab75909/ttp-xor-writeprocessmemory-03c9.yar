rule TTP_XOR_WriteProcessMemory_03c9 {
  strings:
    $key_03c9 = { 54 bb [2] 66 99 [2] 60 ac [2] 4e ac [2] 71 b0 }

  condition:
    any of them
}