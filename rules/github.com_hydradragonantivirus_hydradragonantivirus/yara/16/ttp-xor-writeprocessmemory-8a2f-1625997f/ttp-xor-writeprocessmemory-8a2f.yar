rule TTP_XOR_WriteProcessMemory_8a2f {
  strings:
    $key_8a2f = { dd 5d [2] ef 7f [2] e9 4a [2] c7 4a [2] f8 56 }

  condition:
    any of them
}