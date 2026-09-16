rule TTP_XOR_WriteProcessMemory_58de {
  strings:
    $key_58de = { 0f ac [2] 3d 8e [2] 3b bb [2] 15 bb [2] 2a a7 }

  condition:
    any of them
}