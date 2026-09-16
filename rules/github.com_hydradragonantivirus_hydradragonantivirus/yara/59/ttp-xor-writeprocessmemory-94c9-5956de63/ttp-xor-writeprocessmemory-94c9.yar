rule TTP_XOR_WriteProcessMemory_94c9 {
  strings:
    $key_94c9 = { c3 bb [2] f1 99 [2] f7 ac [2] d9 ac [2] e6 b0 }

  condition:
    any of them
}