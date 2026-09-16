rule TTP_XOR_QUAD_CurrentVersionRun_99cf {
  strings:
    $key_99cf = { ca a0 [2] ee ae [2] c5 82 [2] eb a0 [2] ff bb [2] f0 a1 [2] ee bc [2] ec bd [2] f7 bb [2] eb bc [2] f7 93 }

  condition:
    any of them
}