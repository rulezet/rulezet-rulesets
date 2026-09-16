rule TTP_XOR_QUAD_CurrentVersionRun_80b8 {
  strings:
    $key_80b8 = { d3 d7 [2] f7 d9 [2] dc f5 [2] f2 d7 [2] e6 cc [2] e9 d6 [2] f7 cb [2] f5 ca [2] ee cc [2] f2 cb [2] ee e4 }

  condition:
    any of them
}