rule TTP_XOR_WriteProcessMemory_97d9 {
  strings:
    $key_97d9 = { c0 ab [2] f2 89 [2] f4 bc [2] da bc [2] e5 a0 }

  condition:
    any of them
}