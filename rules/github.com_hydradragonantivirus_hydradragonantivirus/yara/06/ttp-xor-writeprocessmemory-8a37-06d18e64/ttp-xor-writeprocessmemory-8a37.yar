rule TTP_XOR_WriteProcessMemory_8a37 {
  strings:
    $key_8a37 = { dd 45 [2] ef 67 [2] e9 52 [2] c7 52 [2] f8 4e }

  condition:
    any of them
}