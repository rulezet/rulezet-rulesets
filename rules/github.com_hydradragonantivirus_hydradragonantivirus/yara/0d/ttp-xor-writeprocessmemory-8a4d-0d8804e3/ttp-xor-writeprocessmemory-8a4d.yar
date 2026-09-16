rule TTP_XOR_WriteProcessMemory_8a4d {
  strings:
    $key_8a4d = { dd 3f [2] ef 1d [2] e9 28 [2] c7 28 [2] f8 34 }

  condition:
    any of them
}