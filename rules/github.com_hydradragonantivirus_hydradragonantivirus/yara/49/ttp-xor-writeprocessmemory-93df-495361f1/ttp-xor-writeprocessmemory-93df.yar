rule TTP_XOR_WriteProcessMemory_93df {
  strings:
    $key_93df = { c4 ad [2] f6 8f [2] f0 ba [2] de ba [2] e1 a6 }

  condition:
    any of them
}