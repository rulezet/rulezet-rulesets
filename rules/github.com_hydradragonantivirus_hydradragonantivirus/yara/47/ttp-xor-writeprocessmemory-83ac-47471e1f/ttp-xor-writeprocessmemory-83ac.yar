rule TTP_XOR_WriteProcessMemory_83ac {
  strings:
    $key_83ac = { d4 de [2] e6 fc [2] e0 c9 [2] ce c9 [2] f1 d5 }

  condition:
    any of them
}