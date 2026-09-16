rule TTP_XOR_WriteProcessMemory_b0df {
  strings:
    $key_b0df = { e7 ad [2] d5 8f [2] d3 ba [2] fd ba [2] c2 a6 }

  condition:
    any of them
}