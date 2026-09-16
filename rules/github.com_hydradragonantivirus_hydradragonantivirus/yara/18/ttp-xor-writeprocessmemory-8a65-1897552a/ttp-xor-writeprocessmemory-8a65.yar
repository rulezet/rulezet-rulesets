rule TTP_XOR_WriteProcessMemory_8a65 {
  strings:
    $key_8a65 = { dd 17 [2] ef 35 [2] e9 00 [2] c7 00 [2] f8 1c }

  condition:
    any of them
}