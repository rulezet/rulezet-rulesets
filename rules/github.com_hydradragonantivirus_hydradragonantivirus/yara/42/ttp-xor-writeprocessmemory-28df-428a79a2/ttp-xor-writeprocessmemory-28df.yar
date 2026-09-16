rule TTP_XOR_WriteProcessMemory_28df {
  strings:
    $key_28df = { 7f ad [2] 4d 8f [2] 4b ba [2] 65 ba [2] 5a a6 }

  condition:
    any of them
}