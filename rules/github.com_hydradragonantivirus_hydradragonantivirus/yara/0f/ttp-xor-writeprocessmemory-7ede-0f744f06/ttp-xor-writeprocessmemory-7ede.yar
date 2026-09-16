rule TTP_XOR_WriteProcessMemory_7ede {
  strings:
    $key_7ede = { 29 ac [2] 1b 8e [2] 1d bb [2] 33 bb [2] 0c a7 }

  condition:
    any of them
}