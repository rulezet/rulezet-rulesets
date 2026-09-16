rule TTP_XOR_QUAD_CurrentVersionRun_8609 {
  strings:
    $key_8609 = { d5 66 [2] f1 68 [2] da 44 [2] f4 66 [2] e0 7d [2] ef 67 [2] f1 7a [2] f3 7b [2] e8 7d [2] f4 7a [2] e8 55 }

  condition:
    any of them
}