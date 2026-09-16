rule TTP_XOR_WriteProcessMemory_8a6c {
  strings:
    $key_8a6c = { dd 1e [2] ef 3c [2] e9 09 [2] c7 09 [2] f8 15 }

  condition:
    any of them
}