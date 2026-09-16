rule TTP_XOR_WriteProcessMemory_82c3 {
  strings:
    $key_82c3 = { d5 b1 [2] e7 93 [2] e1 a6 [2] cf a6 [2] f0 ba }

  condition:
    any of them
}