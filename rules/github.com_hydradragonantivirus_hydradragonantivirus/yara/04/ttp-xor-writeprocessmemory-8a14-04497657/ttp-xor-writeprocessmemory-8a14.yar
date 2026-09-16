rule TTP_XOR_WriteProcessMemory_8a14 {
  strings:
    $key_8a14 = { dd 66 [2] ef 44 [2] e9 71 [2] c7 71 [2] f8 6d }

  condition:
    any of them
}