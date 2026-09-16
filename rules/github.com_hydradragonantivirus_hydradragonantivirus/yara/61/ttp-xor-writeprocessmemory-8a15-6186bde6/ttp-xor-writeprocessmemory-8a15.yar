rule TTP_XOR_WriteProcessMemory_8a15 {
  strings:
    $key_8a15 = { dd 67 [2] ef 45 [2] e9 70 [2] c7 70 [2] f8 6c }

  condition:
    any of them
}