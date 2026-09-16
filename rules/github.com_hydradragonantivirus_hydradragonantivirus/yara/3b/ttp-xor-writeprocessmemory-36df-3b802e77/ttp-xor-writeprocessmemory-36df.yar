rule TTP_XOR_WriteProcessMemory_36df {
  strings:
    $key_36df = { 61 ad [2] 53 8f [2] 55 ba [2] 7b ba [2] 44 a6 }

  condition:
    any of them
}