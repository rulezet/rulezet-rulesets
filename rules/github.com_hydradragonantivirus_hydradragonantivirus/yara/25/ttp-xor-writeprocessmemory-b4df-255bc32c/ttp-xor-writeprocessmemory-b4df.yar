rule TTP_XOR_WriteProcessMemory_b4df {
  strings:
    $key_b4df = { e3 ad [2] d1 8f [2] d7 ba [2] f9 ba [2] c6 a6 }

  condition:
    any of them
}