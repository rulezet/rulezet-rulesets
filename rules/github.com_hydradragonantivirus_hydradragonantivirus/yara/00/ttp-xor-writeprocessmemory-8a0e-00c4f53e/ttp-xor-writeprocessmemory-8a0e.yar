rule TTP_XOR_WriteProcessMemory_8a0e {
  strings:
    $key_8a0e = { dd 7c [2] ef 5e [2] e9 6b [2] c7 6b [2] f8 77 }

  condition:
    any of them
}