rule TTP_XOR_WriteProcessMemory_82d0 {
  strings:
    $key_82d0 = { d5 a2 [2] e7 80 [2] e1 b5 [2] cf b5 [2] f0 a9 }

  condition:
    any of them
}