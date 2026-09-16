rule TTP_XOR_QUAD_CurrentVersionRun_828b {
  strings:
    $key_828b = { d1 e4 [2] f5 ea [2] de c6 [2] f0 e4 [2] e4 ff [2] eb e5 [2] f5 f8 [2] f7 f9 [2] ec ff [2] f0 f8 [2] ec d7 }

  condition:
    any of them
}