rule TTP_XOR_WriteProcessMemory_8ae5 {
  strings:
    $key_8ae5 = { dd 97 [2] ef b5 [2] e9 80 [2] c7 80 [2] f8 9c }

  condition:
    any of them
}