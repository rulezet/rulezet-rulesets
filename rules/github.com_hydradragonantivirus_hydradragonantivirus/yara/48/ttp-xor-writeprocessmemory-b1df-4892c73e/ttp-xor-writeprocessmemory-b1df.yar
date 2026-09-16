rule TTP_XOR_WriteProcessMemory_b1df {
  strings:
    $key_b1df = { e6 ad [2] d4 8f [2] d2 ba [2] fc ba [2] c3 a6 }

  condition:
    any of them
}