rule TTP_XOR_WriteProcessMemory_8af8 {
  strings:
    $key_8af8 = { dd 8a [2] ef a8 [2] e9 9d [2] c7 9d [2] f8 81 }

  condition:
    any of them
}