rule TTP_XOR_WriteProcessMemory_56df {
  strings:
    $key_56df = { 01 ad [2] 33 8f [2] 35 ba [2] 1b ba [2] 24 a6 }

  condition:
    any of them
}