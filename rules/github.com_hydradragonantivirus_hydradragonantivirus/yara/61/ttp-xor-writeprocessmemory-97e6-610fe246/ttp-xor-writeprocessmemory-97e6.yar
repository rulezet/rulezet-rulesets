rule TTP_XOR_WriteProcessMemory_97e6 {
  strings:
    $key_97e6 = { c0 94 [2] f2 b6 [2] f4 83 [2] da 83 [2] e5 9f }

  condition:
    any of them
}