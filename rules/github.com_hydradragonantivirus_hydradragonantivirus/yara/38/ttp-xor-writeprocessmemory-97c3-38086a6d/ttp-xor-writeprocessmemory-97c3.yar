rule TTP_XOR_WriteProcessMemory_97c3 {
  strings:
    $key_97c3 = { c0 b1 [2] f2 93 [2] f4 a6 [2] da a6 [2] e5 ba }

  condition:
    any of them
}