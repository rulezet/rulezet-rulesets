rule TTP_XOR_WriteProcessMemory_8af7 {
  strings:
    $key_8af7 = { dd 85 [2] ef a7 [2] e9 92 [2] c7 92 [2] f8 8e }

  condition:
    any of them
}