rule TTP_XOR_QUAD_CurrentVersionRun_824b {
  strings:
    $key_824b = { d1 24 [2] f5 2a [2] de 06 [2] f0 24 [2] e4 3f [2] eb 25 [2] f5 38 [2] f7 39 [2] ec 3f [2] f0 38 [2] ec 17 }

  condition:
    any of them
}