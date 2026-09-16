rule TTP_XOR_WriteProcessMemory_8a75 {
  strings:
    $key_8a75 = { dd 07 [2] ef 25 [2] e9 10 [2] c7 10 [2] f8 0c }

  condition:
    any of them
}