rule TTP_XOR_QUAD_CurrentVersionRun_8277 {
  strings:
    $key_8277 = { d1 18 [2] f5 16 [2] de 3a [2] f0 18 [2] e4 03 [2] eb 19 [2] f5 04 [2] f7 05 [2] ec 03 [2] f0 04 [2] ec 2b }

  condition:
    any of them
}