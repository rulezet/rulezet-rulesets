rule TTP_XOR_WriteProcessMemory_19de {
  strings:
    $key_19de = { 4e ac [2] 7c 8e [2] 7a bb [2] 54 bb [2] 6b a7 }

  condition:
    any of them
}