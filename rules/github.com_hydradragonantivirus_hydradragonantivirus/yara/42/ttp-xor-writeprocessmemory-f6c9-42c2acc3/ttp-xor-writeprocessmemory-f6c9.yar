rule TTP_XOR_WriteProcessMemory_f6c9 {
  strings:
    $key_f6c9 = { a1 bb [2] 93 99 [2] 95 ac [2] bb ac [2] 84 b0 }

  condition:
    any of them
}