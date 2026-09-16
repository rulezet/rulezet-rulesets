rule TTP_XOR_WriteProcessMemory_8579 {
  strings:
    $key_8579 = { d2 0b [2] e0 29 [2] e6 1c [2] c8 1c [2] f7 00 }

  condition:
    any of them
}