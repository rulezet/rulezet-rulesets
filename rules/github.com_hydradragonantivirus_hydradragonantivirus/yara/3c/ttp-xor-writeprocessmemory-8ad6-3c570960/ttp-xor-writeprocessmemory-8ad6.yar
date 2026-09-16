rule TTP_XOR_WriteProcessMemory_8ad6 {
  strings:
    $key_8ad6 = { dd a4 [2] ef 86 [2] e9 b3 [2] c7 b3 [2] f8 af }

  condition:
    any of them
}