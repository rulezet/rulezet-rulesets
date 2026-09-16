rule TTP_XOR_QUAD_CurrentVersionRun_8234 {
  strings:
    $key_8234 = { d1 5b [2] f5 55 [2] de 79 [2] f0 5b [2] e4 40 [2] eb 5a [2] f5 47 [2] f7 46 [2] ec 40 [2] f0 47 [2] ec 68 }

  condition:
    any of them
}