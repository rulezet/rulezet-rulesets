rule TTP_XOR_WriteProcessMemory_29de {
  strings:
    $key_29de = { 7e ac [2] 4c 8e [2] 4a bb [2] 64 bb [2] 5b a7 }

  condition:
    any of them
}