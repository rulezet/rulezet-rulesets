rule TTP_XOR_WriteProcessMemory_e7c9 {
  strings:
    $key_e7c9 = { b0 bb [2] 82 99 [2] 84 ac [2] aa ac [2] 95 b0 }

  condition:
    any of them
}