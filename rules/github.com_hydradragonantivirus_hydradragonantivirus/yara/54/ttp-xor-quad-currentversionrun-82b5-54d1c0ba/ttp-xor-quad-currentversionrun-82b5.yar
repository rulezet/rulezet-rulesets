rule TTP_XOR_QUAD_CurrentVersionRun_82b5 {
  strings:
    $key_82b5 = { d1 da [2] f5 d4 [2] de f8 [2] f0 da [2] e4 c1 [2] eb db [2] f5 c6 [2] f7 c7 [2] ec c1 [2] f0 c6 [2] ec e9 }

  condition:
    any of them
}