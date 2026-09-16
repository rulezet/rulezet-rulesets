rule TTP_XOR_WriteProcessMemory_65df {
  strings:
    $key_65df = { 32 ad [2] 00 8f [2] 06 ba [2] 28 ba [2] 17 a6 }

  condition:
    any of them
}