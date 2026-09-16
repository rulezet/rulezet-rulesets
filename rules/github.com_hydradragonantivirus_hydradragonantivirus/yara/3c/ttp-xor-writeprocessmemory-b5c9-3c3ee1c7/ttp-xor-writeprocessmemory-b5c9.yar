rule TTP_XOR_WriteProcessMemory_b5c9 {
  strings:
    $key_b5c9 = { e2 bb [2] d0 99 [2] d6 ac [2] f8 ac [2] c7 b0 }

  condition:
    any of them
}