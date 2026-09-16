rule TTP_XOR_WriteProcessMemory_8ab2 {
  strings:
    $key_8ab2 = { dd c0 [2] ef e2 [2] e9 d7 [2] c7 d7 [2] f8 cb }

  condition:
    any of them
}