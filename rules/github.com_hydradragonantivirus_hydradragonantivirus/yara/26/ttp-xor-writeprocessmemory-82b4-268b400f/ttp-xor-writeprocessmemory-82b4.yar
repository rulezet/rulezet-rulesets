rule TTP_XOR_WriteProcessMemory_82b4 {
  strings:
    $key_82b4 = { d5 c6 [2] e7 e4 [2] e1 d1 [2] cf d1 [2] f0 cd }

  condition:
    any of them
}