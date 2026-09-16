rule TTP_XOR_WriteProcessMemory_00df {
  strings:
    $key_00df = { 57 ad [2] 65 8f [2] 63 ba [2] 4d ba [2] 72 a6 }

  condition:
    any of them
}