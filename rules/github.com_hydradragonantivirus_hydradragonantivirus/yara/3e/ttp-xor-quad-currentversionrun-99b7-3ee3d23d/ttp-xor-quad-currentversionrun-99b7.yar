rule TTP_XOR_QUAD_CurrentVersionRun_99b7 {
  strings:
    $key_99b7 = { ca d8 [2] ee d6 [2] c5 fa [2] eb d8 [2] ff c3 [2] f0 d9 [2] ee c4 [2] ec c5 [2] f7 c3 [2] eb c4 [2] f7 eb }

  condition:
    any of them
}