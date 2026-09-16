rule TTP_XOR_QUAD_CurrentVersionRun_85a5 {
  strings:
    $key_85a5 = { d6 ca [2] f2 c4 [2] d9 e8 [2] f7 ca [2] e3 d1 [2] ec cb [2] f2 d6 [2] f0 d7 [2] eb d1 [2] f7 d6 [2] eb f9 }

  condition:
    any of them
}