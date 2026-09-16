rule TTP_XOR_WriteProcessMemory_a6c9 {
  strings:
    $key_a6c9 = { f1 bb [2] c3 99 [2] c5 ac [2] eb ac [2] d4 b0 }

  condition:
    any of them
}