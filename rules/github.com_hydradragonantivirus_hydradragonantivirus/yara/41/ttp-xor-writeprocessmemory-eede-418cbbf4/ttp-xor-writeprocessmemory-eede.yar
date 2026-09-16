rule TTP_XOR_WriteProcessMemory_eede {
  strings:
    $key_eede = { b9 ac [2] 8b 8e [2] 8d bb [2] a3 bb [2] 9c a7 }

  condition:
    any of them
}