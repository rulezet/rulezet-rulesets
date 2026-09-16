rule TTP_XOR_WriteProcessMemory_8a1e {
  strings:
    $key_8a1e = { dd 6c [2] ef 4e [2] e9 7b [2] c7 7b [2] f8 67 }

  condition:
    any of them
}