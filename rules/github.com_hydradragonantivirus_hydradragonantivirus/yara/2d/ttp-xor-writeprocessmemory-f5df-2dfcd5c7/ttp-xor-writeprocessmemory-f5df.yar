rule TTP_XOR_WriteProcessMemory_f5df {
  strings:
    $key_f5df = { a2 ad [2] 90 8f [2] 96 ba [2] b8 ba [2] 87 a6 }

  condition:
    any of them
}