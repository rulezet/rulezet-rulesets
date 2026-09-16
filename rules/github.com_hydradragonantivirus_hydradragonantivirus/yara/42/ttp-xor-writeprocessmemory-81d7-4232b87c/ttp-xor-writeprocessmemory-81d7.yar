rule TTP_XOR_WriteProcessMemory_81d7 {
  strings:
    $key_81d7 = { d6 a5 [2] e4 87 [2] e2 b2 [2] cc b2 [2] f3 ae }

  condition:
    any of them
}