rule TTP_XOR_WriteProcessMemory_a0df {
  strings:
    $key_a0df = { f7 ad [2] c5 8f [2] c3 ba [2] ed ba [2] d2 a6 }

  condition:
    any of them
}