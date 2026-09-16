rule TTP_XOR_WriteProcessMemory_8af4 {
  strings:
    $key_8af4 = { dd 86 [2] ef a4 [2] e9 91 [2] c7 91 [2] f8 8d }

  condition:
    any of them
}