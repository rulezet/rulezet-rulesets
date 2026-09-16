rule TTP_XOR_QUAD_CurrentVersionRun_8673 {
  strings:
    $key_8673 = { d5 1c [2] f1 12 [2] da 3e [2] f4 1c [2] e0 07 [2] ef 1d [2] f1 00 [2] f3 01 [2] e8 07 [2] f4 00 [2] e8 2f }

  condition:
    any of them
}