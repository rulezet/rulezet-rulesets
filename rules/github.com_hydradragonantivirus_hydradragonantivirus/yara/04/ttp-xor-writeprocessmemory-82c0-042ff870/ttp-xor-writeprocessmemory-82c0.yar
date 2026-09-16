rule TTP_XOR_WriteProcessMemory_82c0 {
  strings:
    $key_82c0 = { d5 b2 [2] e7 90 [2] e1 a5 [2] cf a5 [2] f0 b9 }

  condition:
    any of them
}