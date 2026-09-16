rule TTP_XOR_WriteProcessMemory_8a09 {
  strings:
    $key_8a09 = { dd 7b [2] ef 59 [2] e9 6c [2] c7 6c [2] f8 70 }

  condition:
    any of them
}