rule TTP_XOR_WriteProcessMemory_8a5b {
  strings:
    $key_8a5b = { dd 29 [2] ef 0b [2] e9 3e [2] c7 3e [2] f8 22 }

  condition:
    any of them
}