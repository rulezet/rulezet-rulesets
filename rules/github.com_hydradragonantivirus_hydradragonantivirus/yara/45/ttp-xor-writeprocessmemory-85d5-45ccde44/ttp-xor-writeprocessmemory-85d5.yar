rule TTP_XOR_WriteProcessMemory_85d5 {
  strings:
    $key_85d5 = { d2 a7 [2] e0 85 [2] e6 b0 [2] c8 b0 [2] f7 ac }

  condition:
    any of them
}