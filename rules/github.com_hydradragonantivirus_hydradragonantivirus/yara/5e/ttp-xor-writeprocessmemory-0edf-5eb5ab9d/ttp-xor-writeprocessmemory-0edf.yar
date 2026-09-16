rule TTP_XOR_WriteProcessMemory_0edf {
  strings:
    $key_0edf = { 59 ad [2] 6b 8f [2] 6d ba [2] 43 ba [2] 7c a6 }

  condition:
    any of them
}