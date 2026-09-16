rule TTP_XOR_WriteProcessMemory_8a1b {
  strings:
    $key_8a1b = { dd 69 [2] ef 4b [2] e9 7e [2] c7 7e [2] f8 62 }

  condition:
    any of them
}