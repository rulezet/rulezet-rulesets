rule TTP_XOR_WriteProcessMemory_33c9 {
  strings:
    $key_33c9 = { 64 bb [2] 56 99 [2] 50 ac [2] 7e ac [2] 41 b0 }

  condition:
    any of them
}