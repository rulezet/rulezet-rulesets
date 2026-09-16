rule TTP_XOR_WriteProcessMemory_68de {
  strings:
    $key_68de = { 3f ac [2] 0d 8e [2] 0b bb [2] 25 bb [2] 1a a7 }

  condition:
    any of them
}