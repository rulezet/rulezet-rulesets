rule TTP_XOR_WriteProcessMemory_82d2 {
  strings:
    $key_82d2 = { d5 a0 [2] e7 82 [2] e1 b7 [2] cf b7 [2] f0 ab }

  condition:
    any of them
}