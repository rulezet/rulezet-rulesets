rule TTP_XOR_WriteProcessMemory_97d2 {
  strings:
    $key_97d2 = { c0 a0 [2] f2 82 [2] f4 b7 [2] da b7 [2] e5 ab }

  condition:
    any of them
}