rule TTP_XOR_QUAD_CurrentVersionRun_82c8 {
  strings:
    $key_82c8 = { d1 a7 [2] f5 a9 [2] de 85 [2] f0 a7 [2] e4 bc [2] eb a6 [2] f5 bb [2] f7 ba [2] ec bc [2] f0 bb [2] ec 94 }

  condition:
    any of them
}