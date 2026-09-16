rule TTP_XOR_WriteProcessMemory_8a6b {
  strings:
    $key_8a6b = { dd 19 [2] ef 3b [2] e9 0e [2] c7 0e [2] f8 12 }

  condition:
    any of them
}