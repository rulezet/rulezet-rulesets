rule TTP_XOR_WriteProcessMemory_81a7 {
  strings:
    $key_81a7 = { d6 d5 [2] e4 f7 [2] e2 c2 [2] cc c2 [2] f3 de }

  condition:
    any of them
}