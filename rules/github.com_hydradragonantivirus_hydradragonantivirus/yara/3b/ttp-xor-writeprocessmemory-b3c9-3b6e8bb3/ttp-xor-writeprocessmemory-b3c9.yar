rule TTP_XOR_WriteProcessMemory_b3c9 {
  strings:
    $key_b3c9 = { e4 bb [2] d6 99 [2] d0 ac [2] fe ac [2] c1 b0 }

  condition:
    any of them
}