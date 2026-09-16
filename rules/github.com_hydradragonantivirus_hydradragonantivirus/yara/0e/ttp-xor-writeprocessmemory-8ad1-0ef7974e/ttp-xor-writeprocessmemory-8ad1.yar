rule TTP_XOR_WriteProcessMemory_8ad1 {
  strings:
    $key_8ad1 = { dd a3 [2] ef 81 [2] e9 b4 [2] c7 b4 [2] f8 a8 }

  condition:
    any of them
}