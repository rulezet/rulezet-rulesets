rule TTP_XOR_WriteProcessMemory_8543 {
  strings:
    $key_8543 = { d2 31 [2] e0 13 [2] e6 26 [2] c8 26 [2] f7 3a }

  condition:
    any of them
}