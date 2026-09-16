rule TTP_XOR_WriteProcessMemory_4ede {
  strings:
    $key_4ede = { 19 ac [2] 2b 8e [2] 2d bb [2] 03 bb [2] 3c a7 }

  condition:
    any of them
}