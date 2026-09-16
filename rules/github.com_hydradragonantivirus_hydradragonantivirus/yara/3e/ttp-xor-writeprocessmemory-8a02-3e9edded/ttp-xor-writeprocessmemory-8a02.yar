rule TTP_XOR_WriteProcessMemory_8a02 {
  strings:
    $key_8a02 = { dd 70 [2] ef 52 [2] e9 67 [2] c7 67 [2] f8 7b }

  condition:
    any of them
}