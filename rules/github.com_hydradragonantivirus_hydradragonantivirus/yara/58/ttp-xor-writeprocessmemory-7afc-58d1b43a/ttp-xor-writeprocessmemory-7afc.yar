rule TTP_XOR_WriteProcessMemory_7afc {
  strings:
    $key_7afc = { 2d 8e [2] 1f ac [2] 19 99 [2] 37 99 [2] 08 85 }

  condition:
    any of them
}