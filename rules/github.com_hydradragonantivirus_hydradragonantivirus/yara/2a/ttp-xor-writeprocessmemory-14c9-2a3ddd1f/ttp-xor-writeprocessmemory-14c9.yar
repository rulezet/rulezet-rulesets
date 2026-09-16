rule TTP_XOR_WriteProcessMemory_14c9 {
  strings:
    $key_14c9 = { 43 bb [2] 71 99 [2] 77 ac [2] 59 ac [2] 66 b0 }

  condition:
    any of them
}