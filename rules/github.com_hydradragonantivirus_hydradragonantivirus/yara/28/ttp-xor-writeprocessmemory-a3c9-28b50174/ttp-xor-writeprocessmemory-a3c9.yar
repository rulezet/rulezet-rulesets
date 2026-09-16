rule TTP_XOR_WriteProcessMemory_a3c9 {
  strings:
    $key_a3c9 = { f4 bb [2] c6 99 [2] c0 ac [2] ee ac [2] d1 b0 }

  condition:
    any of them
}