rule TTP_XOR_WriteProcessMemory_81df {
  strings:
    $key_81df = { d6 ad [2] e4 8f [2] e2 ba [2] cc ba [2] f3 a6 }

  condition:
    any of them
}