rule TTP_XOR_QUAD_CurrentVersionRun_71a4 {
  strings:
    $key_71a4 = { 22 cb [2] 06 c5 [2] 2d e9 [2] 03 cb [2] 17 d0 [2] 18 ca [2] 06 d7 [2] 04 d6 [2] 1f d0 [2] 03 d7 [2] 1f f8 }

  condition:
    any of them
}