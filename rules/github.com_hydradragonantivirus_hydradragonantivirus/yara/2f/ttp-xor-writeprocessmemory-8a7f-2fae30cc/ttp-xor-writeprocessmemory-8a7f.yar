rule TTP_XOR_WriteProcessMemory_8a7f {
  strings:
    $key_8a7f = { dd 0d [2] ef 2f [2] e9 1a [2] c7 1a [2] f8 06 }

  condition:
    any of them
}