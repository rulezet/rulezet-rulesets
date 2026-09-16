rule TTP_XOR_WriteProcessMemory_8a07 {
  strings:
    $key_8a07 = { dd 75 [2] ef 57 [2] e9 62 [2] c7 62 [2] f8 7e }

  condition:
    any of them
}