rule TTP_XOR_WriteProcessMemory_8a73 {
  strings:
    $key_8a73 = { dd 01 [2] ef 23 [2] e9 16 [2] c7 16 [2] f8 0a }

  condition:
    any of them
}