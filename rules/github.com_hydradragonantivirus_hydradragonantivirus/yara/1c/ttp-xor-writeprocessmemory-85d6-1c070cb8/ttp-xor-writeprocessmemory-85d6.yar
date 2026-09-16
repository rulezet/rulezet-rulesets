rule TTP_XOR_WriteProcessMemory_85d6 {
  strings:
    $key_85d6 = { d2 a4 [2] e0 86 [2] e6 b3 [2] c8 b3 [2] f7 af }

  condition:
    any of them
}