rule TTP_XOR_QUAD_CurrentVersionRun_85c8 {
  strings:
    $key_85c8 = { d6 a7 [2] f2 a9 [2] d9 85 [2] f7 a7 [2] e3 bc [2] ec a6 [2] f2 bb [2] f0 ba [2] eb bc [2] f7 bb [2] eb 94 }

  condition:
    any of them
}