rule TTP_XOR_WriteProcessMemory_47df {
  strings:
    $key_47df = { 10 ad [2] 22 8f [2] 24 ba [2] 0a ba [2] 35 a6 }

  condition:
    any of them
}