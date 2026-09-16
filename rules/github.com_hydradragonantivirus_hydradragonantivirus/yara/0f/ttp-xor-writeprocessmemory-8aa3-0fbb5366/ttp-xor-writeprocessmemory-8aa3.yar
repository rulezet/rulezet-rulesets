rule TTP_XOR_WriteProcessMemory_8aa3 {
  strings:
    $key_8aa3 = { dd d1 [2] ef f3 [2] e9 c6 [2] c7 c6 [2] f8 da }

  condition:
    any of them
}