rule TTP_XOR_WriteProcessMemory_40df {
  strings:
    $key_40df = { 17 ad [2] 25 8f [2] 23 ba [2] 0d ba [2] 32 a6 }

  condition:
    any of them
}