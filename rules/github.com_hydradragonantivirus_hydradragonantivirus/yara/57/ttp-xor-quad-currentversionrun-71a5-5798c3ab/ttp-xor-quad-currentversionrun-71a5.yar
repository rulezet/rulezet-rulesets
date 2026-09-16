rule TTP_XOR_QUAD_CurrentVersionRun_71a5 {
  strings:
    $key_71a5 = { 22 ca [2] 06 c4 [2] 2d e8 [2] 03 ca [2] 17 d1 [2] 18 cb [2] 06 d6 [2] 04 d7 [2] 1f d1 [2] 03 d6 [2] 1f f9 }

  condition:
    any of them
}