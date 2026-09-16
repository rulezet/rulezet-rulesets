rule TTP_XOR_QUAD_CurrentVersionRun_829c {
  strings:
    $key_829c = { d1 f3 [2] f5 fd [2] de d1 [2] f0 f3 [2] e4 e8 [2] eb f2 [2] f5 ef [2] f7 ee [2] ec e8 [2] f0 ef [2] ec c0 }

  condition:
    any of them
}