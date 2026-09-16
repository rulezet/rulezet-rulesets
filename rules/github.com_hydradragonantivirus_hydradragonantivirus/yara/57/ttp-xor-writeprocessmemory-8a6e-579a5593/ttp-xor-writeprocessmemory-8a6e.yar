rule TTP_XOR_WriteProcessMemory_8a6e {
  strings:
    $key_8a6e = { dd 1c [2] ef 3e [2] e9 0b [2] c7 0b [2] f8 17 }

  condition:
    any of them
}