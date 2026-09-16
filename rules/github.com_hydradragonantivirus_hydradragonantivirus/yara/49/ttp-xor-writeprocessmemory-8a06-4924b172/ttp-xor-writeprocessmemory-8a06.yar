rule TTP_XOR_WriteProcessMemory_8a06 {
  strings:
    $key_8a06 = { dd 74 [2] ef 56 [2] e9 63 [2] c7 63 [2] f8 7f }

  condition:
    any of them
}