rule TTP_XOR_WriteProcessMemory_96b1 {
  strings:
    $key_96b1 = { c1 c3 [2] f3 e1 [2] f5 d4 [2] db d4 [2] e4 c8 }

  condition:
    any of them
}