rule TTP_XOR_WriteProcessMemory_8acd {
  strings:
    $key_8acd = { dd bf [2] ef 9d [2] e9 a8 [2] c7 a8 [2] f8 b4 }

  condition:
    any of them
}