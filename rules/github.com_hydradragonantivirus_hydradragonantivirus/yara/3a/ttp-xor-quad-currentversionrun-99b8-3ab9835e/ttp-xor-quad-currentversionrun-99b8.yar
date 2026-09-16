rule TTP_XOR_QUAD_CurrentVersionRun_99b8 {
  strings:
    $key_99b8 = { ca d7 [2] ee d9 [2] c5 f5 [2] eb d7 [2] ff cc [2] f0 d6 [2] ee cb [2] ec ca [2] f7 cc [2] eb cb [2] f7 e4 }

  condition:
    any of them
}