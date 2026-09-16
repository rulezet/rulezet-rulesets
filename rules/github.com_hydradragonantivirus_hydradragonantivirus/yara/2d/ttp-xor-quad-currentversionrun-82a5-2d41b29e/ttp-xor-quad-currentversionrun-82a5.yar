rule TTP_XOR_QUAD_CurrentVersionRun_82a5 {
  strings:
    $key_82a5 = { d1 ca [2] f5 c4 [2] de e8 [2] f0 ca [2] e4 d1 [2] eb cb [2] f5 d6 [2] f7 d7 [2] ec d1 [2] f0 d6 [2] ec f9 }

  condition:
    any of them
}