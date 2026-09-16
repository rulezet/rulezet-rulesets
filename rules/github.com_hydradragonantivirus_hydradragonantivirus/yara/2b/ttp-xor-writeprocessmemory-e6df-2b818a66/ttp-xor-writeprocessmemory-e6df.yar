rule TTP_XOR_WriteProcessMemory_e6df {
  strings:
    $key_e6df = { b1 ad [2] 83 8f [2] 85 ba [2] ab ba [2] 94 a6 }

  condition:
    any of them
}