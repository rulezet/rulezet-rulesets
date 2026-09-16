rule TTP_XOR_QUAD_CurrentVersionRun_91b8 {
  strings:
    $key_91b8 = { c2 d7 [2] e6 d9 [2] cd f5 [2] e3 d7 [2] f7 cc [2] f8 d6 [2] e6 cb [2] e4 ca [2] ff cc [2] e3 cb [2] ff e4 }

  condition:
    any of them
}