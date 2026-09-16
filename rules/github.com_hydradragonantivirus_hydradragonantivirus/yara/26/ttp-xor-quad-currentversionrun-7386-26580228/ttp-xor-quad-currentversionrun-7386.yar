rule TTP_XOR_QUAD_CurrentVersionRun_7386 {
  strings:
    $key_7386 = { 20 e9 [2] 04 e7 [2] 2f cb [2] 01 e9 [2] 15 f2 [2] 1a e8 [2] 04 f5 [2] 06 f4 [2] 1d f2 [2] 01 f5 [2] 1d da }

  condition:
    any of them
}