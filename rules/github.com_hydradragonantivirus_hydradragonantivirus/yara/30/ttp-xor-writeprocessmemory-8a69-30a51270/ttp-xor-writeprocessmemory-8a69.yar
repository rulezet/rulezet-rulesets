rule TTP_XOR_WriteProcessMemory_8a69 {
  strings:
    $key_8a69 = { dd 1b [2] ef 39 [2] e9 0c [2] c7 0c [2] f8 10 }

  condition:
    any of them
}