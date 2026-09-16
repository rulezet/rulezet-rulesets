rule TTP_XOR_WriteProcessMemory_81d6 {
  strings:
    $key_81d6 = { d6 a4 [2] e4 86 [2] e2 b3 [2] cc b3 [2] f3 af }

  condition:
    any of them
}