rule TTP_XOR_WriteProcessMemory_85e1 {
  strings:
    $key_85e1 = { d2 93 [2] e0 b1 [2] e6 84 [2] c8 84 [2] f7 98 }

  condition:
    any of them
}