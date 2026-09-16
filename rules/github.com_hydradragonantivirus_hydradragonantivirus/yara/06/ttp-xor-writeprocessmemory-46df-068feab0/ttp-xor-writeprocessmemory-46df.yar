rule TTP_XOR_WriteProcessMemory_46df {
  strings:
    $key_46df = { 11 ad [2] 23 8f [2] 25 ba [2] 0b ba [2] 34 a6 }

  condition:
    any of them
}