rule TTP_XOR_WriteProcessMemory_8a61 {
  strings:
    $key_8a61 = { dd 13 [2] ef 31 [2] e9 04 [2] c7 04 [2] f8 18 }

  condition:
    any of them
}