rule TTP_XOR_WriteProcessMemory_8af5 {
  strings:
    $key_8af5 = { dd 87 [2] ef a5 [2] e9 90 [2] c7 90 [2] f8 8c }

  condition:
    any of them
}