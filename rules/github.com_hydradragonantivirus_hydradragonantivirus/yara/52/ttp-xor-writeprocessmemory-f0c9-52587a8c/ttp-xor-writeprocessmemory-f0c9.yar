rule TTP_XOR_WriteProcessMemory_f0c9 {
  strings:
    $key_f0c9 = { a7 bb [2] 95 99 [2] 93 ac [2] bd ac [2] 82 b0 }

  condition:
    any of them
}