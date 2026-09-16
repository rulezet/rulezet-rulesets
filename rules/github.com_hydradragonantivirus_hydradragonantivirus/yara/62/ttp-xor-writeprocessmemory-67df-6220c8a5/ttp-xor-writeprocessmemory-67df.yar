rule TTP_XOR_WriteProcessMemory_67df {
  strings:
    $key_67df = { 30 ad [2] 02 8f [2] 04 ba [2] 2a ba [2] 15 a6 }

  condition:
    any of them
}