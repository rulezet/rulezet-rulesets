rule TTP_XOR_QUAD_CurrentVersionRun_76a5 {
  strings:
    $key_76a5 = { 25 ca [2] 01 c4 [2] 2a e8 [2] 04 ca [2] 10 d1 [2] 1f cb [2] 01 d6 [2] 03 d7 [2] 18 d1 [2] 04 d6 [2] 18 f9 }

  condition:
    any of them
}