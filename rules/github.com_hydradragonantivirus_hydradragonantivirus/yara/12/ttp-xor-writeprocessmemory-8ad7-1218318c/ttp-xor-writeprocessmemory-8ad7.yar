rule TTP_XOR_WriteProcessMemory_8ad7 {
  strings:
    $key_8ad7 = { dd a5 [2] ef 87 [2] e9 b2 [2] c7 b2 [2] f8 ae }

  condition:
    any of them
}