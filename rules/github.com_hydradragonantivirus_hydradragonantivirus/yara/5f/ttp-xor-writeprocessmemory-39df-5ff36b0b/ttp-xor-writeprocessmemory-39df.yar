rule TTP_XOR_WriteProcessMemory_39df {
  strings:
    $key_39df = { 6e ad [2] 5c 8f [2] 5a ba [2] 74 ba [2] 4b a6 }

  condition:
    any of them
}