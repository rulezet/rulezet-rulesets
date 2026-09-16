rule TTP_XOR_WriteProcessMemory_8a5a {
  strings:
    $key_8a5a = { dd 28 [2] ef 0a [2] e9 3f [2] c7 3f [2] f8 23 }

  condition:
    any of them
}