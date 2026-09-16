rule TTP_XOR_WriteProcessMemory_a8de {
  strings:
    $key_a8de = { ff ac [2] cd 8e [2] cb bb [2] e5 bb [2] da a7 }

  condition:
    any of them
}