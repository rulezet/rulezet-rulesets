rule TTP_XOR_WriteProcessMemory_63df {
  strings:
    $key_63df = { 34 ad [2] 06 8f [2] 00 ba [2] 2e ba [2] 11 a6 }

  condition:
    any of them
}