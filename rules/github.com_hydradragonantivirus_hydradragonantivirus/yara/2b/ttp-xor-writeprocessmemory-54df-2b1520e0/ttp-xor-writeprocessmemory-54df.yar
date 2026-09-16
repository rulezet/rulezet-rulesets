rule TTP_XOR_WriteProcessMemory_54df {
  strings:
    $key_54df = { 03 ad [2] 31 8f [2] 37 ba [2] 19 ba [2] 26 a6 }

  condition:
    any of them
}