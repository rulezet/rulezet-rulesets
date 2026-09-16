rule TTP_XOR_WriteProcessMemory_a0c9 {
  strings:
    $key_a0c9 = { f7 bb [2] c5 99 [2] c3 ac [2] ed ac [2] d2 b0 }

  condition:
    any of them
}