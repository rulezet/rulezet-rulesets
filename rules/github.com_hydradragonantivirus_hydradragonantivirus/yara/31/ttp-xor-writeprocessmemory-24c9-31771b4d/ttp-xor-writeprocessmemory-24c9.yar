rule TTP_XOR_WriteProcessMemory_24c9 {
  strings:
    $key_24c9 = { 73 bb [2] 41 99 [2] 47 ac [2] 69 ac [2] 56 b0 }

  condition:
    any of them
}