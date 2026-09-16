rule TTP_XOR_WriteProcessMemory_81dc {
  strings:
    $key_81dc = { d6 ae [2] e4 8c [2] e2 b9 [2] cc b9 [2] f3 a5 }

  condition:
    any of them
}