rule TTP_XOR_WriteProcessMemory_85f2 {
  strings:
    $key_85f2 = { d2 80 [2] e0 a2 [2] e6 97 [2] c8 97 [2] f7 8b }

  condition:
    any of them
}