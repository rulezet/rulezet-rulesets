rule TTP_XOR_WriteProcessMemory_8a41 {
  strings:
    $key_8a41 = { dd 33 [2] ef 11 [2] e9 24 [2] c7 24 [2] f8 38 }

  condition:
    any of them
}