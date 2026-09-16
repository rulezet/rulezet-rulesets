rule TTP_XOR_WriteProcessMemory_8a9e {
  strings:
    $key_8a9e = { dd ec [2] ef ce [2] e9 fb [2] c7 fb [2] f8 e7 }

  condition:
    any of them
}