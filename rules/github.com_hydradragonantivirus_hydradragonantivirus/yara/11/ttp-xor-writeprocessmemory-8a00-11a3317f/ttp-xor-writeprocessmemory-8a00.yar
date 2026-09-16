rule TTP_XOR_WriteProcessMemory_8a00 {
  strings:
    $key_8a00 = { dd 72 [2] ef 50 [2] e9 65 [2] c7 65 [2] f8 79 }

  condition:
    any of them
}