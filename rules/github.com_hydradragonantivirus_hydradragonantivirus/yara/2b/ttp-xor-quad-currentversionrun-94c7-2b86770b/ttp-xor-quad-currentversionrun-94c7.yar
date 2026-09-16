rule TTP_XOR_QUAD_CurrentVersionRun_94c7 {
  strings:
    $key_94c7 = { c7 a8 [2] e3 a6 [2] c8 8a [2] e6 a8 [2] f2 b3 [2] fd a9 [2] e3 b4 [2] e1 b5 [2] fa b3 [2] e6 b4 [2] fa 9b }

  condition:
    any of them
}