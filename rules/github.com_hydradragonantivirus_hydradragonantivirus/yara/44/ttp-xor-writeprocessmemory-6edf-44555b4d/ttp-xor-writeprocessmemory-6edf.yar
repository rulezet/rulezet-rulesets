rule TTP_XOR_WriteProcessMemory_6edf {
  strings:
    $key_6edf = { 39 ad [2] 0b 8f [2] 0d ba [2] 23 ba [2] 1c a6 }

  condition:
    any of them
}