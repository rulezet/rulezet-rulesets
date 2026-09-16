rule TTP_XOR_WriteProcessMemory_8a25 {
  strings:
    $key_8a25 = { dd 57 [2] ef 75 [2] e9 40 [2] c7 40 [2] f8 5c }

  condition:
    any of them
}