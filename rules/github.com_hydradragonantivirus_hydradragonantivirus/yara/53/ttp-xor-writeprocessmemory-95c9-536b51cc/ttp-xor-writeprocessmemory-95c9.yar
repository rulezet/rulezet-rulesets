rule TTP_XOR_WriteProcessMemory_95c9 {
  strings:
    $key_95c9 = { c2 bb [2] f0 99 [2] f6 ac [2] d8 ac [2] e7 b0 }

  condition:
    any of them
}