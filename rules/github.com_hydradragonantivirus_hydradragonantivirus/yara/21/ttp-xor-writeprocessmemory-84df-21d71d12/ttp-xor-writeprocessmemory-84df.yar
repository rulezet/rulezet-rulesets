rule TTP_XOR_WriteProcessMemory_84df {
  strings:
    $key_84df = { d3 ad [2] e1 8f [2] e7 ba [2] c9 ba [2] f6 a6 }

  condition:
    any of them
}