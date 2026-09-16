rule TTP_XOR_WriteProcessMemory_84c8 {
  strings:
    $key_84c8 = { d3 ba [2] e1 98 [2] e7 ad [2] c9 ad [2] f6 b1 }

  condition:
    any of them
}