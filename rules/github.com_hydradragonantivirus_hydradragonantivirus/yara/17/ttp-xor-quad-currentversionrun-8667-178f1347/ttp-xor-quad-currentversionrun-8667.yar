rule TTP_XOR_QUAD_CurrentVersionRun_8667 {
  strings:
    $key_8667 = { d5 08 [2] f1 06 [2] da 2a [2] f4 08 [2] e0 13 [2] ef 09 [2] f1 14 [2] f3 15 [2] e8 13 [2] f4 14 [2] e8 3b }

  condition:
    any of them
}