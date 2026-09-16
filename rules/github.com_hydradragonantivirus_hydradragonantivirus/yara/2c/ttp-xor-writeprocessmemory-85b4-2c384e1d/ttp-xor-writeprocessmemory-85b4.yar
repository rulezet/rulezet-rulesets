rule TTP_XOR_WriteProcessMemory_85b4 {
  strings:
    $key_85b4 = { d2 c6 [2] e0 e4 [2] e6 d1 [2] c8 d1 [2] f7 cd }

  condition:
    any of them
}