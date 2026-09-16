rule TTP_XOR_WriteProcessMemory_8a4b {
  strings:
    $key_8a4b = { dd 39 [2] ef 1b [2] e9 2e [2] c7 2e [2] f8 32 }

  condition:
    any of them
}