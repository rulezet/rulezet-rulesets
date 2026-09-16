rule TTP_XOR_WriteProcessMemory_69df {
  strings:
    $key_69df = { 3e ad [2] 0c 8f [2] 0a ba [2] 24 ba [2] 1b a6 }

  condition:
    any of them
}