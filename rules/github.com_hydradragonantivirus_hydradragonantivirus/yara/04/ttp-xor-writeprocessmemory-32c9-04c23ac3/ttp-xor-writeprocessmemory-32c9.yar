rule TTP_XOR_WriteProcessMemory_32c9 {
  strings:
    $key_32c9 = { 65 bb [2] 57 99 [2] 51 ac [2] 7f ac [2] 40 b0 }

  condition:
    any of them
}