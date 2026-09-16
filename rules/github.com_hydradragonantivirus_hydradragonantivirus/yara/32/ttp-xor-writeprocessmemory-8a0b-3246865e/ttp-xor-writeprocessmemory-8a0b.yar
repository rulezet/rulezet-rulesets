rule TTP_XOR_WriteProcessMemory_8a0b {
  strings:
    $key_8a0b = { dd 79 [2] ef 5b [2] e9 6e [2] c7 6e [2] f8 72 }

  condition:
    any of them
}