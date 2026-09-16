rule TTP_XOR_QUAD_CurrentVersionRun_8619 {
  strings:
    $key_8619 = { d5 76 [2] f1 78 [2] da 54 [2] f4 76 [2] e0 6d [2] ef 77 [2] f1 6a [2] f3 6b [2] e8 6d [2] f4 6a [2] e8 45 }

  condition:
    any of them
}