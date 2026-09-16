rule TTP_XOR_WriteProcessMemory_cffc {
  strings:
    $key_cffc = { 98 8e [2] aa ac [2] ac 99 [2] 82 99 [2] bd 85 }

  condition:
    any of them
}