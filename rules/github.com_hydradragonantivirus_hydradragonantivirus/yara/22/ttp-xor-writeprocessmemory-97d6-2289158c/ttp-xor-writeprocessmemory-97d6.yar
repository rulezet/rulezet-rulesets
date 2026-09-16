rule TTP_XOR_WriteProcessMemory_97d6 {
  strings:
    $key_97d6 = { c0 a4 [2] f2 86 [2] f4 b3 [2] da b3 [2] e5 af }

  condition:
    any of them
}