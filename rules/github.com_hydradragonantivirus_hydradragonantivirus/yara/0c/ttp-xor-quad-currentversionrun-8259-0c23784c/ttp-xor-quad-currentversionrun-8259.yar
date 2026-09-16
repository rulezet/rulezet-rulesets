rule TTP_XOR_QUAD_CurrentVersionRun_8259 {
  strings:
    $key_8259 = { d1 36 [2] f5 38 [2] de 14 [2] f0 36 [2] e4 2d [2] eb 37 [2] f5 2a [2] f7 2b [2] ec 2d [2] f0 2a [2] ec 05 }

  condition:
    any of them
}