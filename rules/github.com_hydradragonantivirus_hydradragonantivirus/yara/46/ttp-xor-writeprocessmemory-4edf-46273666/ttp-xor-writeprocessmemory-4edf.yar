rule TTP_XOR_WriteProcessMemory_4edf {
  strings:
    $key_4edf = { 19 ad [2] 2b 8f [2] 2d ba [2] 03 ba [2] 3c a6 }

  condition:
    any of them
}