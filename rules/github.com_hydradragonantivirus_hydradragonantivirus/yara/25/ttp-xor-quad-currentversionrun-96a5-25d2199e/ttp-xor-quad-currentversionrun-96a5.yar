rule TTP_XOR_QUAD_CurrentVersionRun_96a5 {
  strings:
    $key_96a5 = { c5 ca [2] e1 c4 [2] ca e8 [2] e4 ca [2] f0 d1 [2] ff cb [2] e1 d6 [2] e3 d7 [2] f8 d1 [2] e4 d6 [2] f8 f9 }

  condition:
    any of them
}