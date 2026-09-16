rule TTP_XOR_WriteProcessMemory_81d0 {
  strings:
    $key_81d0 = { d6 a2 [2] e4 80 [2] e2 b5 [2] cc b5 [2] f3 a9 }

  condition:
    any of them
}