rule TTP_XOR_WriteProcessMemory_8a7a {
  strings:
    $key_8a7a = { dd 08 [2] ef 2a [2] e9 1f [2] c7 1f [2] f8 03 }

  condition:
    any of them
}