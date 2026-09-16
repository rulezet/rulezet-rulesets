rule TTP_XOR_WriteProcessMemory_01df {
  strings:
    $key_01df = { 56 ad [2] 64 8f [2] 62 ba [2] 4c ba [2] 73 a6 }

  condition:
    any of them
}