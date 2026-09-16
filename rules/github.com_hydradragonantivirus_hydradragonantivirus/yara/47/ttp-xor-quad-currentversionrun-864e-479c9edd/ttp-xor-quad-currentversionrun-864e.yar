rule TTP_XOR_QUAD_CurrentVersionRun_864e {
  strings:
    $key_864e = { d5 21 [2] f1 2f [2] da 03 [2] f4 21 [2] e0 3a [2] ef 20 [2] f1 3d [2] f3 3c [2] e8 3a [2] f4 3d [2] e8 12 }

  condition:
    any of them
}