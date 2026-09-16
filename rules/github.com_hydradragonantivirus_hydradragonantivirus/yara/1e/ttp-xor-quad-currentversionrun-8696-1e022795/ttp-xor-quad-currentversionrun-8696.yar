rule TTP_XOR_QUAD_CurrentVersionRun_8696 {
  strings:
    $key_8696 = { d5 f9 [2] f1 f7 [2] da db [2] f4 f9 [2] e0 e2 [2] ef f8 [2] f1 e5 [2] f3 e4 [2] e8 e2 [2] f4 e5 [2] e8 ca }

  condition:
    any of them
}