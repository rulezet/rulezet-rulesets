rule TTP_XOR_WriteProcessMemory_96b4 {
  strings:
    $key_96b4 = { c1 c6 [2] f3 e4 [2] f5 d1 [2] db d1 [2] e4 cd }

  condition:
    any of them
}