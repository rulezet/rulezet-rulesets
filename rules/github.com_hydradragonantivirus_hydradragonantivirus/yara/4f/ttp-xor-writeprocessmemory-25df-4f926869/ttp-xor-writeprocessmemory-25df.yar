rule TTP_XOR_WriteProcessMemory_25df {
  strings:
    $key_25df = { 72 ad [2] 40 8f [2] 46 ba [2] 68 ba [2] 57 a6 }

  condition:
    any of them
}