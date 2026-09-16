rule TTP_XOR_WriteProcessMemory_e4df {
  strings:
    $key_e4df = { b3 ad [2] 81 8f [2] 87 ba [2] a9 ba [2] 96 a6 }

  condition:
    any of them
}