rule TTP_XOR_WriteProcessMemory_77df {
  strings:
    $key_77df = { 20 ad [2] 12 8f [2] 14 ba [2] 3a ba [2] 05 a6 }

  condition:
    any of them
}