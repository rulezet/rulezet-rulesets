rule TTP_XOR_QUAD_CurrentVersionRun_82dd {
  strings:
    $key_82dd = { d1 b2 [2] f5 bc [2] de 90 [2] f0 b2 [2] e4 a9 [2] eb b3 [2] f5 ae [2] f7 af [2] ec a9 [2] f0 ae [2] ec 81 }

  condition:
    any of them
}