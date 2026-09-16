rule TTP_XOR_WriteProcessMemory_72c9 {
  strings:
    $key_72c9 = { 25 bb [2] 17 99 [2] 11 ac [2] 3f ac [2] 00 b0 }

  condition:
    any of them
}