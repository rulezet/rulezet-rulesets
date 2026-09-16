rule TTP_XOR_QUAD_CurrentVersionRun_82b4 {
  strings:
    $key_82b4 = { d1 db [2] f5 d5 [2] de f9 [2] f0 db [2] e4 c0 [2] eb da [2] f5 c7 [2] f7 c6 [2] ec c0 [2] f0 c7 [2] ec e8 }

  condition:
    any of them
}