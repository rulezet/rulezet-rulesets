rule TTP_XOR_QUAD_CurrentVersionRun_87b8 {
  strings:
    $key_87b8 = { d4 d7 [2] f0 d9 [2] db f5 [2] f5 d7 [2] e1 cc [2] ee d6 [2] f0 cb [2] f2 ca [2] e9 cc [2] f5 cb [2] e9 e4 }

  condition:
    any of them
}