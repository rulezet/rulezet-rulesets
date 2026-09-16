rule TTP_XOR_WriteProcessMemory_02c9 {
  strings:
    $key_02c9 = { 55 bb [2] 67 99 [2] 61 ac [2] 4f ac [2] 70 b0 }

  condition:
    any of them
}