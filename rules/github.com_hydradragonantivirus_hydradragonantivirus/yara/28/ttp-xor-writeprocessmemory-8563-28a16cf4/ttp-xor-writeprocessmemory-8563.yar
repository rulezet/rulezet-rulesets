rule TTP_XOR_WriteProcessMemory_8563 {
  strings:
    $key_8563 = { d2 11 [2] e0 33 [2] e6 06 [2] c8 06 [2] f7 1a }

  condition:
    any of them
}