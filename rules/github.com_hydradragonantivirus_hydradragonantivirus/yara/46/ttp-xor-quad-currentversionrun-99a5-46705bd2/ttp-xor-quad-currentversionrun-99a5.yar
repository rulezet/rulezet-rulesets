rule TTP_XOR_QUAD_CurrentVersionRun_99a5 {
  strings:
    $key_99a5 = { ca ca [2] ee c4 [2] c5 e8 [2] eb ca [2] ff d1 [2] f0 cb [2] ee d6 [2] ec d7 [2] f7 d1 [2] eb d6 [2] f7 f9 }

  condition:
    any of them
}