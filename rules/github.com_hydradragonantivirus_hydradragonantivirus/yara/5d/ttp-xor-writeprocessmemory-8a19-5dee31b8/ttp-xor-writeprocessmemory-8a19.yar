rule TTP_XOR_WriteProcessMemory_8a19 {
  strings:
    $key_8a19 = { dd 6b [2] ef 49 [2] e9 7c [2] c7 7c [2] f8 60 }

  condition:
    any of them
}