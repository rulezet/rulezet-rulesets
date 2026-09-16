rule TTP_XOR_WriteProcessMemory_b7c9 {
  strings:
    $key_b7c9 = { e0 bb [2] d2 99 [2] d4 ac [2] fa ac [2] c5 b0 }

  condition:
    any of them
}