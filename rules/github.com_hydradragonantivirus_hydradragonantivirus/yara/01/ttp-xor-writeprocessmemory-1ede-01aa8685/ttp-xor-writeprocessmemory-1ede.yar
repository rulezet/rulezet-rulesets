rule TTP_XOR_WriteProcessMemory_1ede {
  strings:
    $key_1ede = { 49 ac [2] 7b 8e [2] 7d bb [2] 53 bb [2] 6c a7 }

  condition:
    any of them
}