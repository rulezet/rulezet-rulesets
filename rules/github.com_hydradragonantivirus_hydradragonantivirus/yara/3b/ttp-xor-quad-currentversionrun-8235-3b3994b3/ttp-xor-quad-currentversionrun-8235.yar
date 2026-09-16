rule TTP_XOR_QUAD_CurrentVersionRun_8235 {
  strings:
    $key_8235 = { d1 5a [2] f5 54 [2] de 78 [2] f0 5a [2] e4 41 [2] eb 5b [2] f5 46 [2] f7 47 [2] ec 41 [2] f0 46 [2] ec 69 }

  condition:
    any of them
}