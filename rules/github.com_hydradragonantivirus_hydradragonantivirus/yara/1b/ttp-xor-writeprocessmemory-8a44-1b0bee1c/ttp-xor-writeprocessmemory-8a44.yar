rule TTP_XOR_WriteProcessMemory_8a44 {
  strings:
    $key_8a44 = { dd 36 [2] ef 14 [2] e9 21 [2] c7 21 [2] f8 3d }

  condition:
    any of them
}