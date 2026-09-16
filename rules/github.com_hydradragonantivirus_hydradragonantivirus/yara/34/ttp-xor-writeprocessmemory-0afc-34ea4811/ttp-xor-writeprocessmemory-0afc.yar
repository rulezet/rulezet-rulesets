rule TTP_XOR_WriteProcessMemory_0afc {
  strings:
    $key_0afc = { 5d 8e [2] 6f ac [2] 69 99 [2] 47 99 [2] 78 85 }

  condition:
    any of them
}