rule TTP_XOR_QUAD_CurrentVersionRun_8669 {
  strings:
    $key_8669 = { d5 06 [2] f1 08 [2] da 24 [2] f4 06 [2] e0 1d [2] ef 07 [2] f1 1a [2] f3 1b [2] e8 1d [2] f4 1a [2] e8 35 }

  condition:
    any of them
}