rule TTP_XOR_WriteProcessMemory_72df {
  strings:
    $key_72df = { 25 ad [2] 17 8f [2] 11 ba [2] 3f ba [2] 00 a6 }

  condition:
    any of them
}