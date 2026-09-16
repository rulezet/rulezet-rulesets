rule TTP_XOR_WriteProcessMemory_8ac4 {
  strings:
    $key_8ac4 = { dd b6 [2] ef 94 [2] e9 a1 [2] c7 a1 [2] f8 bd }

  condition:
    any of them
}