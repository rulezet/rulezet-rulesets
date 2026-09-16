rule TTP_XOR_WriteProcessMemory_21df {
  strings:
    $key_21df = { 76 ad [2] 44 8f [2] 42 ba [2] 6c ba [2] 53 a6 }

  condition:
    any of them
}