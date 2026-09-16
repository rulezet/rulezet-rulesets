rule TTP_XOR_WriteProcessMemory_82d1 {
  strings:
    $key_82d1 = { d5 a3 [2] e7 81 [2] e1 b4 [2] cf b4 [2] f0 a8 }

  condition:
    any of them
}