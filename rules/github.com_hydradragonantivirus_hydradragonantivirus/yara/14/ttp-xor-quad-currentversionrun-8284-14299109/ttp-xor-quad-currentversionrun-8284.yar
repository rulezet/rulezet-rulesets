rule TTP_XOR_QUAD_CurrentVersionRun_8284 {
  strings:
    $key_8284 = { d1 eb [2] f5 e5 [2] de c9 [2] f0 eb [2] e4 f0 [2] eb ea [2] f5 f7 [2] f7 f6 [2] ec f0 [2] f0 f7 [2] ec d8 }

  condition:
    any of them
}