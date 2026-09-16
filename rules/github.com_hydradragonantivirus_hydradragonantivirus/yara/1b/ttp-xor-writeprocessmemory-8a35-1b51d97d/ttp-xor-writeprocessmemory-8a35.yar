rule TTP_XOR_WriteProcessMemory_8a35 {
  strings:
    $key_8a35 = { dd 47 [2] ef 65 [2] e9 50 [2] c7 50 [2] f8 4c }

  condition:
    any of them
}