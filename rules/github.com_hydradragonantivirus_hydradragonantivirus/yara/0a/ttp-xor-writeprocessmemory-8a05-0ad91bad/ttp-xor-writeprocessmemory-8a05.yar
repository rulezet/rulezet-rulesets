rule TTP_XOR_WriteProcessMemory_8a05 {
  strings:
    $key_8a05 = { dd 77 [2] ef 55 [2] e9 60 [2] c7 60 [2] f8 7c }

  condition:
    any of them
}