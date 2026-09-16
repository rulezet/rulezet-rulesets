rule TTP_XOR_WriteProcessMemory_8ac8 {
  strings:
    $key_8ac8 = { dd ba [2] ef 98 [2] e9 ad [2] c7 ad [2] f8 b1 }

  condition:
    any of them
}