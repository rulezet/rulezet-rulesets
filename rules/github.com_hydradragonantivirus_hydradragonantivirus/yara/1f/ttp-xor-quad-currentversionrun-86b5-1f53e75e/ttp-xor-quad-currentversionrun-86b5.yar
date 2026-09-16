rule TTP_XOR_QUAD_CurrentVersionRun_86b5 {
  strings:
    $key_86b5 = { d5 da [2] f1 d4 [2] da f8 [2] f4 da [2] e0 c1 [2] ef db [2] f1 c6 [2] f3 c7 [2] e8 c1 [2] f4 c6 [2] e8 e9 }

  condition:
    any of them
}