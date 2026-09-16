rule TTP_XOR_WriteProcessMemory_82a0 {
  strings:
    $key_82a0 = { d5 d2 [2] e7 f0 [2] e1 c5 [2] cf c5 [2] f0 d9 }

  condition:
    any of them
}