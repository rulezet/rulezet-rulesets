rule TTP_XOR_WriteProcessMemory_7ffc {
  strings:
    $key_7ffc = { 28 8e [2] 1a ac [2] 1c 99 [2] 32 99 [2] 0d 85 }

  condition:
    any of them
}