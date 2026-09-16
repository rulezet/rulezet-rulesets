rule TTP_XOR_WriteProcessMemory_81d5 {
  strings:
    $key_81d5 = { d6 a7 [2] e4 85 [2] e2 b0 [2] cc b0 [2] f3 ac }

  condition:
    any of them
}