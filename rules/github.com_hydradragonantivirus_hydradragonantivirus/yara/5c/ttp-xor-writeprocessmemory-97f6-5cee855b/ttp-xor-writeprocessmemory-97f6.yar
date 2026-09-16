rule TTP_XOR_WriteProcessMemory_97f6 {
  strings:
    $key_97f6 = { c0 84 [2] f2 a6 [2] f4 93 [2] da 93 [2] e5 8f }

  condition:
    any of them
}