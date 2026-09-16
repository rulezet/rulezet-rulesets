rule TTP_XOR_WriteProcessMemory_85a7 {
  strings:
    $key_85a7 = { d2 d5 [2] e0 f7 [2] e6 c2 [2] c8 c2 [2] f7 de }

  condition:
    any of them
}