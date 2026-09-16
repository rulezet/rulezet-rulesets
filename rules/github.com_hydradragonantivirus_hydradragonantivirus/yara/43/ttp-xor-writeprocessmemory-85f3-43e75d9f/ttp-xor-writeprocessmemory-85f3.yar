rule TTP_XOR_WriteProcessMemory_85f3 {
  strings:
    $key_85f3 = { d2 81 [2] e0 a3 [2] e6 96 [2] c8 96 [2] f7 8a }

  condition:
    any of them
}