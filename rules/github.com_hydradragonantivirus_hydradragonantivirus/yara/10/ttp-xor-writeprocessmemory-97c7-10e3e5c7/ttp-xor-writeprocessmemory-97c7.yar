rule TTP_XOR_WriteProcessMemory_97c7 {
  strings:
    $key_97c7 = { c0 b5 [2] f2 97 [2] f4 a2 [2] da a2 [2] e5 be }

  condition:
    any of them
}