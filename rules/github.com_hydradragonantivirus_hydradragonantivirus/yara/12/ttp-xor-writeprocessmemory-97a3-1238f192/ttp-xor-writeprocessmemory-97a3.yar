rule TTP_XOR_WriteProcessMemory_97a3 {
  strings:
    $key_97a3 = { c0 d1 [2] f2 f3 [2] f4 c6 [2] da c6 [2] e5 da }

  condition:
    any of them
}