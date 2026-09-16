rule TTP_XOR_WriteProcessMemory_2ede {
  strings:
    $key_2ede = { 79 ac [2] 4b 8e [2] 4d bb [2] 63 bb [2] 5c a7 }

  condition:
    any of them
}