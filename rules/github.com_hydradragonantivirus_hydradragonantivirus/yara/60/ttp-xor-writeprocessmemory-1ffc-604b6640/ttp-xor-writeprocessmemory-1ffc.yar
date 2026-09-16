rule TTP_XOR_WriteProcessMemory_1ffc {
  strings:
    $key_1ffc = { 48 8e [2] 7a ac [2] 7c 99 [2] 52 99 [2] 6d 85 }

  condition:
    any of them
}