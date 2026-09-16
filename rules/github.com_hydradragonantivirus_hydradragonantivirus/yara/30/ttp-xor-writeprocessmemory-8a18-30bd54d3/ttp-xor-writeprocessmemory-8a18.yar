rule TTP_XOR_WriteProcessMemory_8a18 {
  strings:
    $key_8a18 = { dd 6a [2] ef 48 [2] e9 7d [2] c7 7d [2] f8 61 }

  condition:
    any of them
}