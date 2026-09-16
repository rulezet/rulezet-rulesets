rule TTP_XOR_WriteProcessMemory_11df {
  strings:
    $key_11df = { 46 ad [2] 74 8f [2] 72 ba [2] 5c ba [2] 63 a6 }

  condition:
    any of them
}