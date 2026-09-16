rule TTP_XOR_QUAD_CurrentVersionRun_8264 {
  strings:
    $key_8264 = { d1 0b [2] f5 05 [2] de 29 [2] f0 0b [2] e4 10 [2] eb 0a [2] f5 17 [2] f7 16 [2] ec 10 [2] f0 17 [2] ec 38 }

  condition:
    any of them
}