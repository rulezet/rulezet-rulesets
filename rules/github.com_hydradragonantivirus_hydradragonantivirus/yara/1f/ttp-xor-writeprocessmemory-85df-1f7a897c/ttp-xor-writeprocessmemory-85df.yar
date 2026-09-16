rule TTP_XOR_WriteProcessMemory_85df {
  strings:
    $key_85df = { d2 ad [2] e0 8f [2] e6 ba [2] c8 ba [2] f7 a6 }

  condition:
    any of them
}