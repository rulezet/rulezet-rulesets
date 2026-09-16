rule TTP_XOR_WriteProcessMemory_64df {
  strings:
    $key_64df = { 33 ad [2] 01 8f [2] 07 ba [2] 29 ba [2] 16 a6 }

  condition:
    any of them
}