rule TTP_XOR_WriteProcessMemory_8a2e {
  strings:
    $key_8a2e = { dd 5c [2] ef 7e [2] e9 4b [2] c7 4b [2] f8 57 }

  condition:
    any of them
}