rule TTP_XOR_WriteProcessMemory_5ffc {
  strings:
    $key_5ffc = { 08 8e [2] 3a ac [2] 3c 99 [2] 12 99 [2] 2d 85 }

  condition:
    any of them
}