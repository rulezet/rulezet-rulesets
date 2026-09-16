rule TTP_XOR_WriteProcessMemory_8a38 {
  strings:
    $key_8a38 = { dd 4a [2] ef 68 [2] e9 5d [2] c7 5d [2] f8 41 }

  condition:
    any of them
}