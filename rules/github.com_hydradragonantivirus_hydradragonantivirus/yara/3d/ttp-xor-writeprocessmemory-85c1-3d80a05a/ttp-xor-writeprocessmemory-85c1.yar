rule TTP_XOR_WriteProcessMemory_85c1 {
  strings:
    $key_85c1 = { d2 b3 [2] e0 91 [2] e6 a4 [2] c8 a4 [2] f7 b8 }

  condition:
    any of them
}