rule TTP_XOR_WriteProcessMemory_8a03 {
  strings:
    $key_8a03 = { dd 71 [2] ef 53 [2] e9 66 [2] c7 66 [2] f8 7a }

  condition:
    any of them
}