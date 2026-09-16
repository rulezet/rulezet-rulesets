rule TTP_XOR_WriteProcessMemory_96c8 {
  strings:
    $key_96c8 = { c1 ba [2] f3 98 [2] f5 ad [2] db ad [2] e4 b1 }

  condition:
    any of them
}