rule TTP_XOR_WriteProcessMemory_85c0 {
  strings:
    $key_85c0 = { d2 b2 [2] e0 90 [2] e6 a5 [2] c8 a5 [2] f7 b9 }

  condition:
    any of them
}