rule TTP_XOR_WriteProcessMemory_8a39 {
  strings:
    $key_8a39 = { dd 4b [2] ef 69 [2] e9 5c [2] c7 5c [2] f8 40 }

  condition:
    any of them
}