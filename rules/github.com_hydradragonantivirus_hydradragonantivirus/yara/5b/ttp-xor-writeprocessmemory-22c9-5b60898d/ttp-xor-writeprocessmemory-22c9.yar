rule TTP_XOR_WriteProcessMemory_22c9 {
  strings:
    $key_22c9 = { 75 bb [2] 47 99 [2] 41 ac [2] 6f ac [2] 50 b0 }

  condition:
    any of them
}