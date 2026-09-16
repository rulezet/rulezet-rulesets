rule TTP_XOR_WriteProcessMemory_23c9 {
  strings:
    $key_23c9 = { 74 bb [2] 46 99 [2] 40 ac [2] 6e ac [2] 51 b0 }

  condition:
    any of them
}