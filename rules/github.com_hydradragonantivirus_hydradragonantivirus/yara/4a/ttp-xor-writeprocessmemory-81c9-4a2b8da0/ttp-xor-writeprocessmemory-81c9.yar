rule TTP_XOR_WriteProcessMemory_81c9 {
  strings:
    $key_81c9 = { d6 bb [2] e4 99 [2] e2 ac [2] cc ac [2] f3 b0 }

  condition:
    any of them
}