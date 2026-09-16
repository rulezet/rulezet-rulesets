rule TTP_XOR_WriteProcessMemory_39fc {
  strings:
    $key_39fc = { 6e 8e [2] 5c ac [2] 5a 99 [2] 74 99 [2] 4b 85 }

  condition:
    any of them
}