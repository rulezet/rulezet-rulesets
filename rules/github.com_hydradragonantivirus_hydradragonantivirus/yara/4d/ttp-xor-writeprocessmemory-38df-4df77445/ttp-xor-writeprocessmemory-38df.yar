rule TTP_XOR_WriteProcessMemory_38df {
  strings:
    $key_38df = { 6f ad [2] 5d 8f [2] 5b ba [2] 75 ba [2] 4a a6 }

  condition:
    any of them
}