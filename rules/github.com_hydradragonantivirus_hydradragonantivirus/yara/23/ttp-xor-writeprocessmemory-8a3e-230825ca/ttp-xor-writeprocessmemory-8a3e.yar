rule TTP_XOR_WriteProcessMemory_8a3e {
  strings:
    $key_8a3e = { dd 4c [2] ef 6e [2] e9 5b [2] c7 5b [2] f8 47 }

  condition:
    any of them
}