rule TTP_XOR_WriteProcessMemory_8a16 {
  strings:
    $key_8a16 = { dd 64 [2] ef 46 [2] e9 73 [2] c7 73 [2] f8 6f }

  condition:
    any of them
}