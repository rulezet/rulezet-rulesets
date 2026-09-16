rule TTP_XOR_WriteProcessMemory_8530 {
  strings:
    $key_8530 = { d2 42 [2] e0 60 [2] e6 55 [2] c8 55 [2] f7 49 }

  condition:
    any of them
}