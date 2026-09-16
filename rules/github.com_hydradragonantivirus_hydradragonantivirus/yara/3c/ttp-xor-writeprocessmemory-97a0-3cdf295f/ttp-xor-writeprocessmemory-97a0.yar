rule TTP_XOR_WriteProcessMemory_97a0 {
  strings:
    $key_97a0 = { c0 d2 [2] f2 f0 [2] f4 c5 [2] da c5 [2] e5 d9 }

  condition:
    any of them
}