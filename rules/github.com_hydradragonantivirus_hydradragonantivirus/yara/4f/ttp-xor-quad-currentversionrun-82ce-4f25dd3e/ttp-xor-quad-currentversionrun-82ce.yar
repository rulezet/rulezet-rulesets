rule TTP_XOR_QUAD_CurrentVersionRun_82ce {
  strings:
    $key_82ce = { d1 a1 [2] f5 af [2] de 83 [2] f0 a1 [2] e4 ba [2] eb a0 [2] f5 bd [2] f7 bc [2] ec ba [2] f0 bd [2] ec 92 }

  condition:
    any of them
}