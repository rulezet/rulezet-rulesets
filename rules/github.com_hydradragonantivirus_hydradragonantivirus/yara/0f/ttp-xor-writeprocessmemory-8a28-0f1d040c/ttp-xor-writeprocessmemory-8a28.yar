rule TTP_XOR_WriteProcessMemory_8a28 {
  strings:
    $key_8a28 = { dd 5a [2] ef 78 [2] e9 4d [2] c7 4d [2] f8 51 }

  condition:
    any of them
}