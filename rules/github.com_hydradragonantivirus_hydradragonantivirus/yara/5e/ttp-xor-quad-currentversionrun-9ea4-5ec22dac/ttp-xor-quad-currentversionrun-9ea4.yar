rule TTP_XOR_QUAD_CurrentVersionRun_9ea4 {
  strings:
    $key_9ea4 = { cd cb [2] e9 c5 [2] c2 e9 [2] ec cb [2] f8 d0 [2] f7 ca [2] e9 d7 [2] eb d6 [2] f0 d0 [2] ec d7 [2] f0 f8 }

  condition:
    any of them
}