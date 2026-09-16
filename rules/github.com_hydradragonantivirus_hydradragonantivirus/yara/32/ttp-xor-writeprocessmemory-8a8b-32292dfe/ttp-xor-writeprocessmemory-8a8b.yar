rule TTP_XOR_WriteProcessMemory_8a8b {
  strings:
    $key_8a8b = { dd f9 [2] ef db [2] e9 ee [2] c7 ee [2] f8 f2 }

  condition:
    any of them
}