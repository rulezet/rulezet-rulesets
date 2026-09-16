rule TTP_XOR_QUAD_CurrentVersionRun_96b8 {
  strings:
    $key_96b8 = { c5 d7 [2] e1 d9 [2] ca f5 [2] e4 d7 [2] f0 cc [2] ff d6 [2] e1 cb [2] e3 ca [2] f8 cc [2] e4 cb [2] f8 e4 }

  condition:
    any of them
}