rule TTP_XOR_WriteProcessMemory_8a84 {
  strings:
    $key_8a84 = { dd f6 [2] ef d4 [2] e9 e1 [2] c7 e1 [2] f8 fd }

  condition:
    any of them
}