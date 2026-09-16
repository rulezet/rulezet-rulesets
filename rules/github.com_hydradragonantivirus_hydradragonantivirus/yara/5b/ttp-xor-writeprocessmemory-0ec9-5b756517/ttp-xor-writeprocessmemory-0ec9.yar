rule TTP_XOR_WriteProcessMemory_0ec9 {
  strings:
    $key_0ec9 = { 59 bb [2] 6b 99 [2] 6d ac [2] 43 ac [2] 7c b0 }

  condition:
    any of them
}