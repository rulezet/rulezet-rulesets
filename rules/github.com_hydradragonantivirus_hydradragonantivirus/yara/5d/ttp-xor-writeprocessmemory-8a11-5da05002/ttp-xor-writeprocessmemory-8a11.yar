rule TTP_XOR_WriteProcessMemory_8a11 {
  strings:
    $key_8a11 = { dd 63 [2] ef 41 [2] e9 74 [2] c7 74 [2] f8 68 }

  condition:
    any of them
}