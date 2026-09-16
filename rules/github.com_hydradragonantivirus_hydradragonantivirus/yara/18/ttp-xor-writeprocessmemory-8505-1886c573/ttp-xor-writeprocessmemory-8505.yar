rule TTP_XOR_WriteProcessMemory_8505 {
  strings:
    $key_8505 = { d2 77 [2] e0 55 [2] e6 60 [2] c8 60 [2] f7 7c }

  condition:
    any of them
}