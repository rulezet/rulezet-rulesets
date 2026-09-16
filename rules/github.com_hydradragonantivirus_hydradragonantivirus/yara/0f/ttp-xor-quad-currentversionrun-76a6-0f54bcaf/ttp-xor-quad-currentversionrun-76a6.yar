rule TTP_XOR_QUAD_CurrentVersionRun_76a6 {
  strings:
    $key_76a6 = { 25 c9 [2] 01 c7 [2] 2a eb [2] 04 c9 [2] 10 d2 [2] 1f c8 [2] 01 d5 [2] 03 d4 [2] 18 d2 [2] 04 d5 [2] 18 fa }

  condition:
    any of them
}