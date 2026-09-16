rule TTP_XOR_WriteProcessMemory_82c4 {
  strings:
    $key_82c4 = { d5 b6 [2] e7 94 [2] e1 a1 [2] cf a1 [2] f0 bd }

  condition:
    any of them
}