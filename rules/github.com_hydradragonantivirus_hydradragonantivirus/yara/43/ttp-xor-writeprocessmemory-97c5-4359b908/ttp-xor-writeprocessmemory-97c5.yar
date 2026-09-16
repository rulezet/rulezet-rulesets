rule TTP_XOR_WriteProcessMemory_97c5 {
  strings:
    $key_97c5 = { c0 b7 [2] f2 95 [2] f4 a0 [2] da a0 [2] e5 bc }

  condition:
    any of them
}