rule TTP_XOR_QUAD_CurrentVersionRun_41a5 {
  strings:
    $key_41a5 = { 12 ca [2] 36 c4 [2] 1d e8 [2] 33 ca [2] 27 d1 [2] 28 cb [2] 36 d6 [2] 34 d7 [2] 2f d1 [2] 33 d6 [2] 2f f9 }

  condition:
    any of them
}