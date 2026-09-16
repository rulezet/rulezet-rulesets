rule TTP_XOR_WriteProcessMemory_3bfc {
  strings:
    $key_3bfc = { 6c 8e [2] 5e ac [2] 58 99 [2] 76 99 [2] 49 85 }

  condition:
    any of them
}