rule TTP_XOR_WriteProcessMemory_8a7d {
  strings:
    $key_8a7d = { dd 0f [2] ef 2d [2] e9 18 [2] c7 18 [2] f8 04 }

  condition:
    any of them
}