rule TTP_XOR_WriteProcessMemory_8ae1 {
  strings:
    $key_8ae1 = { dd 93 [2] ef b1 [2] e9 84 [2] c7 84 [2] f8 98 }

  condition:
    any of them
}