rule TTP_XOR_WriteProcessMemory_8a52 {
  strings:
    $key_8a52 = { dd 20 [2] ef 02 [2] e9 37 [2] c7 37 [2] f8 2b }

  condition:
    any of them
}