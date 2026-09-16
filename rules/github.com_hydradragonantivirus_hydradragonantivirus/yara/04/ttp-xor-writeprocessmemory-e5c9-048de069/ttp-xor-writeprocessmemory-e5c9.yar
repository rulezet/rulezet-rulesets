rule TTP_XOR_WriteProcessMemory_e5c9 {
  strings:
    $key_e5c9 = { b2 bb [2] 80 99 [2] 86 ac [2] a8 ac [2] 97 b0 }

  condition:
    any of them
}