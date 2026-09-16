rule TTP_XOR_WriteProcessMemory_69de {
  strings:
    $key_69de = { 3e ac [2] 0c 8e [2] 0a bb [2] 24 bb [2] 1b a7 }

  condition:
    any of them
}