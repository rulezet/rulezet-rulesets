rule TTP_XOR_WriteProcessMemory_a5df {
  strings:
    $key_a5df = { f2 ad [2] c0 8f [2] c6 ba [2] e8 ba [2] d7 a6 }

  condition:
    any of them
}