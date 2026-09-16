rule TTP_XOR_WriteProcessMemory_8ae4 {
  strings:
    $key_8ae4 = { dd 96 [2] ef b4 [2] e9 81 [2] c7 81 [2] f8 9d }

  condition:
    any of them
}