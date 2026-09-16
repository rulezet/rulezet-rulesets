rule TTP_XOR_WriteProcessMemory_8abc {
  strings:
    $key_8abc = { dd ce [2] ef ec [2] e9 d9 [2] c7 d9 [2] f8 c5 }

  condition:
    any of them
}