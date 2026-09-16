rule TTP_XOR_WriteProcessMemory_82c7 {
  strings:
    $key_82c7 = { d5 b5 [2] e7 97 [2] e1 a2 [2] cf a2 [2] f0 be }

  condition:
    any of them
}