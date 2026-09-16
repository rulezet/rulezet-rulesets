rule TTP_XOR_WriteProcessMemory_44df {
  strings:
    $key_44df = { 13 ad [2] 21 8f [2] 27 ba [2] 09 ba [2] 36 a6 }

  condition:
    any of them
}