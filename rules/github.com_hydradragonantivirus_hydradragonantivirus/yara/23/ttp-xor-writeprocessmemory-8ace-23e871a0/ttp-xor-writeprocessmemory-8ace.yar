rule TTP_XOR_WriteProcessMemory_8ace {
  strings:
    $key_8ace = { dd bc [2] ef 9e [2] e9 ab [2] c7 ab [2] f8 b7 }

  condition:
    any of them
}