rule TTP_XOR_WriteProcessMemory_85b2 {
  strings:
    $key_85b2 = { d2 c0 [2] e0 e2 [2] e6 d7 [2] c8 d7 [2] f7 cb }

  condition:
    any of them
}