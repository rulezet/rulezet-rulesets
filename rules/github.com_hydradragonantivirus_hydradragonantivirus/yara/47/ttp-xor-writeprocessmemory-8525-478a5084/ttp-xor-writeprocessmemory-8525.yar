rule TTP_XOR_WriteProcessMemory_8525 {
  strings:
    $key_8525 = { d2 57 [2] e0 75 [2] e6 40 [2] c8 40 [2] f7 5c }

  condition:
    any of them
}