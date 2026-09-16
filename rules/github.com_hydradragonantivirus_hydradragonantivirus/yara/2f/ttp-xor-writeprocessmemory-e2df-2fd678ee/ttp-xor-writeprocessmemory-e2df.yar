rule TTP_XOR_WriteProcessMemory_e2df {
  strings:
    $key_e2df = { b5 ad [2] 87 8f [2] 81 ba [2] af ba [2] 90 a6 }

  condition:
    any of them
}