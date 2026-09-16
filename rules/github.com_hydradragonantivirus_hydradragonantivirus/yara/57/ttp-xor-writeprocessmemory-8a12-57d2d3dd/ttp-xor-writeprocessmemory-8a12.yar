rule TTP_XOR_WriteProcessMemory_8a12 {
  strings:
    $key_8a12 = { dd 60 [2] ef 42 [2] e9 77 [2] c7 77 [2] f8 6b }

  condition:
    any of them
}