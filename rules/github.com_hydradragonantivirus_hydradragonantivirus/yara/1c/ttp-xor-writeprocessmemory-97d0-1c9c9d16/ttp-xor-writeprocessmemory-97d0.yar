rule TTP_XOR_WriteProcessMemory_97d0 {
  strings:
    $key_97d0 = { c0 a2 [2] f2 80 [2] f4 b5 [2] da b5 [2] e5 a9 }

  condition:
    any of them
}