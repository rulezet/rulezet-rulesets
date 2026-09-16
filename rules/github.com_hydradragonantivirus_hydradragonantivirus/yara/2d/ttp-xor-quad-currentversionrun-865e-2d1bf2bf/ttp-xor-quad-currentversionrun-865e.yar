rule TTP_XOR_QUAD_CurrentVersionRun_865e {
  strings:
    $key_865e = { d5 31 [2] f1 3f [2] da 13 [2] f4 31 [2] e0 2a [2] ef 30 [2] f1 2d [2] f3 2c [2] e8 2a [2] f4 2d [2] e8 02 }

  condition:
    any of them
}