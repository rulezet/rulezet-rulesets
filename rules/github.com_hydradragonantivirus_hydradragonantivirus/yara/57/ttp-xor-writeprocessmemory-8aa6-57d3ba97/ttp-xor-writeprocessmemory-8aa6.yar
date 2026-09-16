rule TTP_XOR_WriteProcessMemory_8aa6 {
  strings:
    $key_8aa6 = { dd d4 [2] ef f6 [2] e9 c3 [2] c7 c3 [2] f8 df }

  condition:
    any of them
}