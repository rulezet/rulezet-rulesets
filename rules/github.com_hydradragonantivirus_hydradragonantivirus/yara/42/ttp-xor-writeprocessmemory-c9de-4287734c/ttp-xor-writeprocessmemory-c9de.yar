rule TTP_XOR_WriteProcessMemory_c9de {
  strings:
    $key_c9de = { 9e ac [2] ac 8e [2] aa bb [2] 84 bb [2] bb a7 }

  condition:
    any of them
}