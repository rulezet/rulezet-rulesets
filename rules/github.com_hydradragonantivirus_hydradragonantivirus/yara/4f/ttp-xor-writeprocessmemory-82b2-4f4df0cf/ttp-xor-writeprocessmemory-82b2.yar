rule TTP_XOR_WriteProcessMemory_82b2 {
  strings:
    $key_82b2 = { d5 c0 [2] e7 e2 [2] e1 d7 [2] cf d7 [2] f0 cb }

  condition:
    any of them
}