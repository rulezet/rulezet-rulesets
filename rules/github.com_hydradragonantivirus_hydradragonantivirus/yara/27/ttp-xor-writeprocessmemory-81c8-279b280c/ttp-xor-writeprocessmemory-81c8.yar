rule TTP_XOR_WriteProcessMemory_81c8 {
  strings:
    $key_81c8 = { d6 ba [2] e4 98 [2] e2 ad [2] cc ad [2] f3 b1 }

  condition:
    any of them
}