rule TTP_XOR_WriteProcessMemory_8a2b {
  strings:
    $key_8a2b = { dd 59 [2] ef 7b [2] e9 4e [2] c7 4e [2] f8 52 }

  condition:
    any of them
}