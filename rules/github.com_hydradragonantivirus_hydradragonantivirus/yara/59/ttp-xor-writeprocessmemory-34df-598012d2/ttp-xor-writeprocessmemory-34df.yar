rule TTP_XOR_WriteProcessMemory_34df {
  strings:
    $key_34df = { 63 ad [2] 51 8f [2] 57 ba [2] 79 ba [2] 46 a6 }

  condition:
    any of them
}