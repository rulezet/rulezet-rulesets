rule TTP_XOR_WriteProcessMemory_32df {
  strings:
    $key_32df = { 65 ad [2] 57 8f [2] 51 ba [2] 7f ba [2] 40 a6 }

  condition:
    any of them
}