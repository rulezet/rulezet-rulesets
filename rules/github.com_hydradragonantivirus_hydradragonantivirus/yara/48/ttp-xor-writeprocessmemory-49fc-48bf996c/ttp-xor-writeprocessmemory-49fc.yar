rule TTP_XOR_WriteProcessMemory_49fc {
  strings:
    $key_49fc = { 1e 8e [2] 2c ac [2] 2a 99 [2] 04 99 [2] 3b 85 }

  condition:
    any of them
}