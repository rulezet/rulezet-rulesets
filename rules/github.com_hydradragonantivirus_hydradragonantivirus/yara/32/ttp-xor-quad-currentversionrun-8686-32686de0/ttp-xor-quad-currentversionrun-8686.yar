rule TTP_XOR_QUAD_CurrentVersionRun_8686 {
  strings:
    $key_8686 = { d5 e9 [2] f1 e7 [2] da cb [2] f4 e9 [2] e0 f2 [2] ef e8 [2] f1 f5 [2] f3 f4 [2] e8 f2 [2] f4 f5 [2] e8 da }

  condition:
    any of them
}