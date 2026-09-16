rule TTP_XOR_WriteProcessMemory_8ab9 {
  strings:
    $key_8ab9 = { dd cb [2] ef e9 [2] e9 dc [2] c7 dc [2] f8 c0 }

  condition:
    any of them
}