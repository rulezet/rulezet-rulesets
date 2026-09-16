rule TTP_XOR_QUAD_CurrentVersionRun_8675 {
  strings:
    $key_8675 = { d5 1a [2] f1 14 [2] da 38 [2] f4 1a [2] e0 01 [2] ef 1b [2] f1 06 [2] f3 07 [2] e8 01 [2] f4 06 [2] e8 29 }

  condition:
    any of them
}