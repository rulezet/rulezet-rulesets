rule TTP_XOR_WriteProcessMemory_80df {
  strings:
    $key_80df = { d7 ad [2] e5 8f [2] e3 ba [2] cd ba [2] f2 a6 }

  condition:
    any of them
}