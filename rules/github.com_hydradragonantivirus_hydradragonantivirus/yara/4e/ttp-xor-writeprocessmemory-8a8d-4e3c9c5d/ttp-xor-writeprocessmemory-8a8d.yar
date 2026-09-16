rule TTP_XOR_WriteProcessMemory_8a8d {
  strings:
    $key_8a8d = { dd ff [2] ef dd [2] e9 e8 [2] c7 e8 [2] f8 f4 }

  condition:
    any of them
}