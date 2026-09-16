rule TTP_XOR_WriteProcessMemory_8a3c {
  strings:
    $key_8a3c = { dd 4e [2] ef 6c [2] e9 59 [2] c7 59 [2] f8 45 }

  condition:
    any of them
}