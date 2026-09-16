rule TTP_XOR_WriteProcessMemory_8a1a {
  strings:
    $key_8a1a = { dd 68 [2] ef 4a [2] e9 7f [2] c7 7f [2] f8 63 }

  condition:
    any of them
}