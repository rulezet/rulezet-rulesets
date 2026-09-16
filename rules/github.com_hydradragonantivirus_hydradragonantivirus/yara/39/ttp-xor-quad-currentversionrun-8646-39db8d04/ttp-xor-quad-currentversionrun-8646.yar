rule TTP_XOR_QUAD_CurrentVersionRun_8646 {
  strings:
    $key_8646 = { d5 29 [2] f1 27 [2] da 0b [2] f4 29 [2] e0 32 [2] ef 28 [2] f1 35 [2] f3 34 [2] e8 32 [2] f4 35 [2] e8 1a }

  condition:
    any of them
}