rule TTP_XOR_WriteProcessMemory_3ec9 {
  strings:
    $key_3ec9 = { 69 bb [2] 5b 99 [2] 5d ac [2] 73 ac [2] 4c b0 }

  condition:
    any of them
}