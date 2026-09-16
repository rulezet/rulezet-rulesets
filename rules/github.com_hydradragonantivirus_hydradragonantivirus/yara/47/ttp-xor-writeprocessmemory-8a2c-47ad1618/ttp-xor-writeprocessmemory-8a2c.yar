rule TTP_XOR_WriteProcessMemory_8a2c {
  strings:
    $key_8a2c = { dd 5e [2] ef 7c [2] e9 49 [2] c7 49 [2] f8 55 }

  condition:
    any of them
}