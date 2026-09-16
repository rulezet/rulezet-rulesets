rule TTP_XOR_QUAD_CurrentVersionRun_cf95 {
  strings:
    $key_cf95 = { 9c fa [2] b8 f4 [2] 93 d8 [2] bd fa [2] a9 e1 [2] a6 fb [2] b8 e6 [2] ba e7 [2] a1 e1 [2] bd e6 [2] a1 c9 }

  condition:
    any of them
}