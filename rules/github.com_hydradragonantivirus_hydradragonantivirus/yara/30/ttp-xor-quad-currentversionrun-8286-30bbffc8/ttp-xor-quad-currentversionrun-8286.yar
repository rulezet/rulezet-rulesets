rule TTP_XOR_QUAD_CurrentVersionRun_8286 {
  strings:
    $key_8286 = { d1 e9 [2] f5 e7 [2] de cb [2] f0 e9 [2] e4 f2 [2] eb e8 [2] f5 f5 [2] f7 f4 [2] ec f2 [2] f0 f5 [2] ec da }

  condition:
    any of them
}