rule TTP_XOR_WriteProcessMemory_82d4 {
  strings:
    $key_82d4 = { d5 a6 [2] e7 84 [2] e1 b1 [2] cf b1 [2] f0 ad }

  condition:
    any of them
}