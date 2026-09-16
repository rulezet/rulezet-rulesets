rule TTP_XOR_WriteProcessMemory_5bfc {
  strings:
    $key_5bfc = { 0c 8e [2] 3e ac [2] 38 99 [2] 16 99 [2] 29 85 }

  condition:
    any of them
}