rule TTP_XOR_WriteProcessMemory_28de {
  strings:
    $key_28de = { 7f ac [2] 4d 8e [2] 4b bb [2] 65 bb [2] 5a a7 }

  condition:
    any of them
}