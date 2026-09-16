rule TTP_XOR_QUAD_CurrentVersionRun_8246 {
  strings:
    $key_8246 = { d1 29 [2] f5 27 [2] de 0b [2] f0 29 [2] e4 32 [2] eb 28 [2] f5 35 [2] f7 34 [2] ec 32 [2] f0 35 [2] ec 1a }

  condition:
    any of them
}