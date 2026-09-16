rule TTP_XOR_QUAD_CurrentVersionRun_8275 {
  strings:
    $key_8275 = { d1 1a [2] f5 14 [2] de 38 [2] f0 1a [2] e4 01 [2] eb 1b [2] f5 06 [2] f7 07 [2] ec 01 [2] f0 06 [2] ec 29 }

  condition:
    any of them
}