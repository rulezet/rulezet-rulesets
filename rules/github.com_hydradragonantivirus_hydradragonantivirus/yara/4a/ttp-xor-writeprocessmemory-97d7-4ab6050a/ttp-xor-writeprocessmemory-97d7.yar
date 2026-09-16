rule TTP_XOR_WriteProcessMemory_97d7 {
  strings:
    $key_97d7 = { c0 a5 [2] f2 87 [2] f4 b2 [2] da b2 [2] e5 ae }

  condition:
    any of them
}