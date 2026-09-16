rule TTP_XOR_WriteProcessMemory_a4df {
  strings:
    $key_a4df = { f3 ad [2] c1 8f [2] c7 ba [2] e9 ba [2] d6 a6 }

  condition:
    any of them
}