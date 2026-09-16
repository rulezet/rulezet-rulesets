rule TTP_XOR_QUAD_CurrentVersionRun_87a5 {
  strings:
    $key_87a5 = { d4 ca [2] f0 c4 [2] db e8 [2] f5 ca [2] e1 d1 [2] ee cb [2] f0 d6 [2] f2 d7 [2] e9 d1 [2] f5 d6 [2] e9 f9 }

  condition:
    any of them
}