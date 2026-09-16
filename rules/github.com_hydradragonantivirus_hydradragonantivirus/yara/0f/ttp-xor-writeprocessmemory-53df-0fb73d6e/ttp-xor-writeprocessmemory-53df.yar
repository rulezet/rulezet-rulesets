rule TTP_XOR_WriteProcessMemory_53df {
  strings:
    $key_53df = { 04 ad [2] 36 8f [2] 30 ba [2] 1e ba [2] 21 a6 }

  condition:
    any of them
}