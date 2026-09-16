rule TTP_XOR_WriteProcessMemory_52c9 {
  strings:
    $key_52c9 = { 05 bb [2] 37 99 [2] 31 ac [2] 1f ac [2] 20 b0 }

  condition:
    any of them
}