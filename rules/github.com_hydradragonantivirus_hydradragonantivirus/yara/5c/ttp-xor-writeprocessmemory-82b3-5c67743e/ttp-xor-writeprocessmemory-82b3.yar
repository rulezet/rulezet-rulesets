rule TTP_XOR_WriteProcessMemory_82b3 {
  strings:
    $key_82b3 = { d5 c1 [2] e7 e3 [2] e1 d6 [2] cf d6 [2] f0 ca }

  condition:
    any of them
}