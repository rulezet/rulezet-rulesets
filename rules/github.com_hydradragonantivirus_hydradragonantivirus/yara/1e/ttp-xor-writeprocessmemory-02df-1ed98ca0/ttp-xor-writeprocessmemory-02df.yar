rule TTP_XOR_WriteProcessMemory_02df {
  strings:
    $key_02df = { 55 ad [2] 67 8f [2] 61 ba [2] 4f ba [2] 70 a6 }

  condition:
    any of them
}