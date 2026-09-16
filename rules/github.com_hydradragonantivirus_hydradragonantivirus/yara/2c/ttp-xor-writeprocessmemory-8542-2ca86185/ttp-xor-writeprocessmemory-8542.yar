rule TTP_XOR_WriteProcessMemory_8542 {
  strings:
    $key_8542 = { d2 30 [2] e0 12 [2] e6 27 [2] c8 27 [2] f7 3b }

  condition:
    any of them
}