rule TTP_XOR_QUAD_CurrentVersionRun_95b8 {
  strings:
    $key_95b8 = { c6 d7 [2] e2 d9 [2] c9 f5 [2] e7 d7 [2] f3 cc [2] fc d6 [2] e2 cb [2] e0 ca [2] fb cc [2] e7 cb [2] fb e4 }

  condition:
    any of them
}