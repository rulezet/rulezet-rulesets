rule TTP_XOR_WriteProcessMemory_17df {
  strings:
    $key_17df = { 40 ad [2] 72 8f [2] 74 ba [2] 5a ba [2] 65 a6 }

  condition:
    any of them
}