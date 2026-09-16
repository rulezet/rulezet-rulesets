rule TTP_XOR_WriteProcessMemory_8a22 {
  strings:
    $key_8a22 = { dd 50 [2] ef 72 [2] e9 47 [2] c7 47 [2] f8 5b }

  condition:
    any of them
}