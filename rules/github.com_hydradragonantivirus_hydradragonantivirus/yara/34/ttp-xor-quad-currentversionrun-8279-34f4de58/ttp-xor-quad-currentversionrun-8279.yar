rule TTP_XOR_QUAD_CurrentVersionRun_8279 {
  strings:
    $key_8279 = { d1 16 [2] f5 18 [2] de 34 [2] f0 16 [2] e4 0d [2] eb 17 [2] f5 0a [2] f7 0b [2] ec 0d [2] f0 0a [2] ec 25 }

  condition:
    any of them
}