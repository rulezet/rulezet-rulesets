rule TTP_XOR_QUAD_CurrentVersionRun_8228 {
  strings:
    $key_8228 = { d1 47 [2] f5 49 [2] de 65 [2] f0 47 [2] e4 5c [2] eb 46 [2] f5 5b [2] f7 5a [2] ec 5c [2] f0 5b [2] ec 74 }

  condition:
    any of them
}