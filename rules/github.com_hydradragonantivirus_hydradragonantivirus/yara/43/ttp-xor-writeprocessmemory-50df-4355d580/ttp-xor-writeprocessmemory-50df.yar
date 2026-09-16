rule TTP_XOR_WriteProcessMemory_50df {
  strings:
    $key_50df = { 07 ad [2] 35 8f [2] 33 ba [2] 1d ba [2] 22 a6 }

  condition:
    any of them
}