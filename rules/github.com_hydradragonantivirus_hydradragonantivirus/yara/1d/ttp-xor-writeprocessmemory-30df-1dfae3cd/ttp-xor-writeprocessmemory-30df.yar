rule TTP_XOR_WriteProcessMemory_30df {
  strings:
    $key_30df = { 67 ad [2] 55 8f [2] 53 ba [2] 7d ba [2] 42 a6 }

  condition:
    any of them
}