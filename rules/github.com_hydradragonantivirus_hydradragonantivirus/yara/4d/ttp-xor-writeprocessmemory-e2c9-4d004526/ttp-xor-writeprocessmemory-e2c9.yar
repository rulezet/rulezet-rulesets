rule TTP_XOR_WriteProcessMemory_e2c9 {
  strings:
    $key_e2c9 = { b5 bb [2] 87 99 [2] 81 ac [2] af ac [2] 90 b0 }

  condition:
    any of them
}