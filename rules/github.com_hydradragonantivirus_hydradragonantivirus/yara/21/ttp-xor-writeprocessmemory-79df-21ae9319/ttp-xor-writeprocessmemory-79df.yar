rule TTP_XOR_WriteProcessMemory_79df {
  strings:
    $key_79df = { 2e ad [2] 1c 8f [2] 1a ba [2] 34 ba [2] 0b a6 }

  condition:
    any of them
}