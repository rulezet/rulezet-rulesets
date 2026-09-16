rule TTP_XOR_QUAD_CurrentVersionRun_8257 {
  strings:
    $key_8257 = { d1 38 [2] f5 36 [2] de 1a [2] f0 38 [2] e4 23 [2] eb 39 [2] f5 24 [2] f7 25 [2] ec 23 [2] f0 24 [2] ec 0b }

  condition:
    any of them
}