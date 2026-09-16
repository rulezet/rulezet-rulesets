rule TTP_XOR_WriteProcessMemory_42c9 {
  strings:
    $key_42c9 = { 15 bb [2] 27 99 [2] 21 ac [2] 0f ac [2] 30 b0 }

  condition:
    any of them
}