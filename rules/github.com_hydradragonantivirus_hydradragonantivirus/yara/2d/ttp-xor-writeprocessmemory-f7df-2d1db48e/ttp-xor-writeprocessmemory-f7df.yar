rule TTP_XOR_WriteProcessMemory_f7df {
  strings:
    $key_f7df = { a0 ad [2] 92 8f [2] 94 ba [2] ba ba [2] 85 a6 }

  condition:
    any of them
}