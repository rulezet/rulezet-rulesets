rule TTP_XOR_WriteProcessMemory_71df {
  strings:
    $key_71df = { 26 ad [2] 14 8f [2] 12 ba [2] 3c ba [2] 03 a6 }

  condition:
    any of them
}