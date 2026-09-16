rule TTP_XOR_WriteProcessMemory_85c7 {
  strings:
    $key_85c7 = { d2 b5 [2] e0 97 [2] e6 a2 [2] c8 a2 [2] f7 be }

  condition:
    any of them
}