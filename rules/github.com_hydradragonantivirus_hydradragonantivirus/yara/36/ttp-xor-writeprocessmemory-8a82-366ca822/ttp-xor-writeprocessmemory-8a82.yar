rule TTP_XOR_WriteProcessMemory_8a82 {
  strings:
    $key_8a82 = { dd f0 [2] ef d2 [2] e9 e7 [2] c7 e7 [2] f8 fb }

  condition:
    any of them
}