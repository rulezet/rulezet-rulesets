rule TTP_XOR_WriteProcessMemory_18df {
  strings:
    $key_18df = { 4f ad [2] 7d 8f [2] 7b ba [2] 55 ba [2] 6a a6 }

  condition:
    any of them
}