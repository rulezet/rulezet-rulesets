rule TTP_XOR_WriteProcessMemory_8a43 {
  strings:
    $key_8a43 = { dd 31 [2] ef 13 [2] e9 26 [2] c7 26 [2] f8 3a }

  condition:
    any of them
}