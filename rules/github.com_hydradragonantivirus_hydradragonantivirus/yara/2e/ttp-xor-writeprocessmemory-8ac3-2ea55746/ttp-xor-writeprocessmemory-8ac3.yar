rule TTP_XOR_WriteProcessMemory_8ac3 {
  strings:
    $key_8ac3 = { dd b1 [2] ef 93 [2] e9 a6 [2] c7 a6 [2] f8 ba }

  condition:
    any of them
}